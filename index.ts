/**
 * SwarmOrchestrator - Multi-Agent Swarm Orchestration Skill
 * 
 * This module implements the core logic for agent-to-agent communication,
 * task decomposition, permission management, and shared blackboard coordination.
 * 
 * @module SwarmOrchestrator
 * @version 1.0.0
 * @license MIT
 */

import { OpenClawSkill, SkillContext, SkillResult, callSkill } from 'openclaw-core';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import { randomUUID } from 'crypto';

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

interface TaskPayload {
  instruction: string;
  context?: Record<string, unknown>;
  constraints?: string[];
  expectedOutput?: string;
}

interface HandoffMessage {
  handoffId: string;
  sourceAgent: string;
  targetAgent: string;
  taskType: 'delegate' | 'collaborate' | 'validate';
  payload: TaskPayload;
  metadata: {
    priority: number;
    deadline: number;
    parentTaskId: string | null;
  };
}

interface PermissionGrant {
  granted: boolean;
  grantToken: string | null;
  expiresAt: string | null;
  restrictions: string[];
  reason?: string;
}

interface SwarmState {
  timestamp: string;
  activeAgents: AgentStatus[];
  pendingTasks: TaskRecord[];
  blackboardSnapshot: Record<string, BlackboardEntry>;
  permissionGrants: ActiveGrant[];
}

interface AgentStatus {
  agentId: string;
  status: 'available' | 'busy' | 'waiting_auth' | 'offline';
  currentTask: string | null;
  lastHeartbeat: string;
}

interface TaskRecord {
  taskId: string;
  agentId: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  startedAt: string;
  description: string;
}

interface BlackboardEntry {
  key: string;
  value: unknown;
  sourceAgent: string;
  timestamp: string;
  ttl: number | null;
}

interface ActiveGrant {
  grantToken: string;
  resourceType: string;
  agentId: string;
  expiresAt: string;
}

interface ParallelTask {
  agentType: string;
  taskPayload: TaskPayload;
}

interface ParallelExecutionResult {
  synthesizedResult: unknown;
  individualResults: Array<{
    agentType: string;
    success: boolean;
    result: unknown;
    executionTime: number;
  }>;
  executionMetrics: {
    totalTime: number;
    successRate: number;
    synthesisStrategy: string;
  };
}

type SynthesisStrategy = 'merge' | 'vote' | 'chain' | 'first-success';

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
  blackboardPath: './swarm-blackboard.md',
  maxParallelAgents: 3,
  defaultTimeout: 30000,
  enableTracing: true,
  grantTokenTTL: 300000, // 5 minutes in milliseconds
};

// ============================================================================
// BLACKBOARD MANAGEMENT
// ============================================================================

class SharedBlackboard {
  private path: string;
  private cache: Map<string, BlackboardEntry> = new Map();

  constructor(basePath: string) {
    this.path = join(basePath, 'swarm-blackboard.md');
    this.initialize();
  }

  private initialize(): void {
    if (!existsSync(this.path)) {
      const initialContent = `# Swarm Blackboard
Last Updated: ${new Date().toISOString()}

## Active Tasks
| TaskID | Agent | Status | Started | Description |
|--------|-------|--------|---------|-------------|

## Knowledge Cache
<!-- Cached results from agent operations -->

## Coordination Signals
<!-- Agent availability status -->

## Execution History
<!-- Chronological log of completed tasks -->
`;
      writeFileSync(this.path, initialContent, 'utf-8');
    }
    this.loadFromDisk();
  }

  private loadFromDisk(): void {
    try {
      const content = readFileSync(this.path, 'utf-8');
      // Parse blackboard entries from markdown
      const cacheSection = content.match(/## Knowledge Cache\n([\s\S]*?)(?=\n## |$)/);
      if (cacheSection) {
        const entries = cacheSection[1].matchAll(/### (\S+)\n([\s\S]*?)(?=\n### |$)/g);
        for (const entry of entries) {
          const key = entry[1];
          try {
            const metadata = JSON.parse(entry[2].trim());
            this.cache.set(key, metadata);
          } catch {
            // Skip malformed entries
          }
        }
      }
    } catch (error) {
      console.error('[Blackboard] Failed to load from disk:', error);
    }
  }

  private persistToDisk(): void {
    const sections = [
      `# Swarm Blackboard`,
      `Last Updated: ${new Date().toISOString()}`,
      ``,
      `## Active Tasks`,
      `| TaskID | Agent | Status | Started | Description |`,
      `|--------|-------|--------|---------|-------------|`,
      ``,
      `## Knowledge Cache`,
    ];

    for (const [key, entry] of this.cache.entries()) {
      if (entry.ttl && Date.now() > new Date(entry.timestamp).getTime() + entry.ttl * 1000) {
        this.cache.delete(key);
        continue;
      }
      sections.push(`### ${key}`);
      sections.push(JSON.stringify(entry, null, 2));
      sections.push('');
    }

    sections.push(`## Coordination Signals`);
    sections.push(`## Execution History`);

    writeFileSync(this.path, sections.join('\n'), 'utf-8');
  }

  read(key: string): BlackboardEntry | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    // Check TTL
    if (entry.ttl) {
      const expiresAt = new Date(entry.timestamp).getTime() + entry.ttl * 1000;
      if (Date.now() > expiresAt) {
        this.cache.delete(key);
        this.persistToDisk();
        return null;
      }
    }

    return entry;
  }

  write(key: string, value: unknown, sourceAgent: string, ttl?: number): BlackboardEntry {
    const entry: BlackboardEntry = {
      key,
      value,
      sourceAgent,
      timestamp: new Date().toISOString(),
      ttl: ttl ?? null,
    };

    this.cache.set(key, entry);
    this.persistToDisk();
    return entry;
  }

  exists(key: string): boolean {
    return this.read(key) !== null;
  }

  getSnapshot(): Record<string, BlackboardEntry> {
    const snapshot: Record<string, BlackboardEntry> = {};
    for (const [key, entry] of this.cache.entries()) {
      if (this.read(key)) { // This checks TTL
        snapshot[key] = entry;
      }
    }
    return snapshot;
  }
}

// ============================================================================
// AUTH GUARDIAN - PERMISSION WALL IMPLEMENTATION
// ============================================================================

class AuthGuardian {
  private activeGrants: Map<string, ActiveGrant> = new Map();
  private agentTrustLevels: Map<string, number> = new Map();
  private auditLog: Array<{ timestamp: string; action: string; details: unknown }> = [];

  constructor() {
    // Initialize with default trust levels
    this.agentTrustLevels.set('orchestrator', 0.9);
    this.agentTrustLevels.set('data_analyst', 0.8);
    this.agentTrustLevels.set('strategy_advisor', 0.7);
    this.agentTrustLevels.set('risk_assessor', 0.85);
  }

  async requestPermission(
    agentId: string,
    resourceType: 'SAP_API' | 'FINANCIAL_API' | 'EXTERNAL_SERVICE' | 'DATA_EXPORT',
    justification: string,
    scope?: string
  ): Promise<PermissionGrant> {
    this.log('permission_request', { agentId, resourceType, justification, scope });

    // Evaluate the permission request
    const evaluation = this.evaluateRequest(agentId, resourceType, justification, scope);

    if (!evaluation.approved) {
      return {
        granted: false,
        grantToken: null,
        expiresAt: null,
        restrictions: [],
        reason: evaluation.reason,
      };
    }

    // Generate grant token
    const grantToken = this.generateGrantToken();
    const expiresAt = new Date(Date.now() + CONFIG.grantTokenTTL).toISOString();

    const grant: ActiveGrant = {
      grantToken,
      resourceType,
      agentId,
      expiresAt,
    };

    this.activeGrants.set(grantToken, grant);
    this.log('permission_granted', { grantToken, agentId, resourceType, expiresAt });

    return {
      granted: true,
      grantToken,
      expiresAt,
      restrictions: evaluation.restrictions,
    };
  }

  validateToken(token: string): boolean {
    const grant = this.activeGrants.get(token);
    if (!grant) return false;

    if (new Date(grant.expiresAt) < new Date()) {
      this.activeGrants.delete(token);
      return false;
    }

    return true;
  }

  revokeToken(token: string): void {
    this.activeGrants.delete(token);
    this.log('permission_revoked', { token });
  }

  private evaluateRequest(
    agentId: string,
    resourceType: string,
    justification: string,
    scope?: string
  ): { approved: boolean; reason?: string; restrictions: string[] } {
    const restrictions: string[] = [];

    // 1. Justification Quality (40% weight)
    const justificationScore = this.scoreJustification(justification);
    if (justificationScore < 0.3) {
      return {
        approved: false,
        reason: 'Justification is insufficient. Please provide specific task context.',
        restrictions: [],
      };
    }

    // 2. Agent Trust Level (30% weight)
    const trustLevel = this.agentTrustLevels.get(agentId) ?? 0.5;
    if (trustLevel < 0.4) {
      return {
        approved: false,
        reason: 'Agent trust level is below threshold. Escalate to human operator.',
        restrictions: [],
      };
    }

    // 3. Risk Assessment (30% weight)
    const riskScore = this.assessRisk(resourceType, scope);
    if (riskScore > 0.8) {
      return {
        approved: false,
        reason: 'Risk assessment exceeds acceptable threshold. Narrow the requested scope.',
        restrictions: [],
      };
    }

    // Determine restrictions based on resource type
    switch (resourceType) {
      case 'SAP_API':
        restrictions.push('read_only', 'max_records:100');
        break;
      case 'FINANCIAL_API':
        restrictions.push('read_only', 'no_pii_fields', 'audit_required');
        break;
      case 'EXTERNAL_SERVICE':
        restrictions.push('rate_limit:10_per_minute');
        break;
      case 'DATA_EXPORT':
        restrictions.push('anonymize_pii', 'local_only');
        break;
    }

    // Calculate weighted approval
    const weightedScore = (justificationScore * 0.4) + (trustLevel * 0.3) + ((1 - riskScore) * 0.3);
    const approved = weightedScore >= 0.5;

    return {
      approved,
      reason: approved ? undefined : 'Combined evaluation score below threshold.',
      restrictions,
    };
  }

  private scoreJustification(justification: string): number {
    // Simple heuristic scoring for justification quality
    let score = 0;

    if (justification.length > 20) score += 0.2;
    if (justification.length > 50) score += 0.2;
    if (/task|purpose|need|require/i.test(justification)) score += 0.2;
    if (/specific|particular|exact/i.test(justification)) score += 0.2;
    if (!/test|debug|try/i.test(justification)) score += 0.2;

    return Math.min(score, 1);
  }

  private assessRisk(resourceType: string, scope?: string): number {
    const baseRisks: Record<string, number> = {
      'SAP_API': 0.5,
      'FINANCIAL_API': 0.7,
      'EXTERNAL_SERVICE': 0.4,
      'DATA_EXPORT': 0.6,
    };

    let risk = baseRisks[resourceType] ?? 0.5;

    // Broad scopes increase risk
    if (!scope || scope === '*' || scope === 'all') {
      risk += 0.2;
    }

    // Write operations increase risk
    if (scope && /write|delete|update|modify/i.test(scope)) {
      risk += 0.2;
    }

    return Math.min(risk, 1);
  }

  private generateGrantToken(): string {
    return `grant_${randomUUID().replace(/-/g, '')}`;
  }

  private log(action: string, details: unknown): void {
    this.auditLog.push({
      timestamp: new Date().toISOString(),
      action,
      details,
    });
  }

  getActiveGrants(): ActiveGrant[] {
    // Clean expired grants
    const now = new Date();
    for (const [token, grant] of this.activeGrants.entries()) {
      if (new Date(grant.expiresAt) < now) {
        this.activeGrants.delete(token);
      }
    }
    return Array.from(this.activeGrants.values());
  }
}

// ============================================================================
// TASK DECOMPOSITION ENGINE
// ============================================================================

class TaskDecomposer {
  private blackboard: SharedBlackboard;
  private authGuardian: AuthGuardian;

  constructor(blackboard: SharedBlackboard, authGuardian: AuthGuardian) {
    this.blackboard = blackboard;
    this.authGuardian = authGuardian;
  }

  /**
   * Decomposes a complex task into parallel sub-agent calls
   * This is the "Wall Breaker" - transforms impossible monolithic tasks
   * into manageable parallel executions
   */
  async executeParallel(
    tasks: ParallelTask[],
    synthesisStrategy: SynthesisStrategy = 'merge',
    context: SkillContext
  ): Promise<ParallelExecutionResult> {
    // Enforce maximum parallel agent limit
    if (tasks.length > CONFIG.maxParallelAgents) {
      throw new Error(
        `Cannot spawn ${tasks.length} agents. Maximum is ${CONFIG.maxParallelAgents}. ` +
        `Decompose further or use 'chain' strategy.`
      );
    }

    const startTime = Date.now();
    const individualResults: ParallelExecutionResult['individualResults'] = [];

    // Check blackboard for cached results first
    const cachedTasks: ParallelTask[] = [];
    const uncachedTasks: ParallelTask[] = [];

    for (const task of tasks) {
      const cacheKey = `task:${task.agentType}:${this.hashPayload(task.taskPayload)}`;
      const cached = this.blackboard.read(cacheKey);

      if (cached) {
        individualResults.push({
          agentType: task.agentType,
          success: true,
          result: cached.value,
          executionTime: 0, // From cache
        });
        cachedTasks.push(task);
      } else {
        uncachedTasks.push(task);
      }
    }

    // Execute uncached tasks in parallel using Promise.all
    if (uncachedTasks.length > 0) {
      const parallelPromises = uncachedTasks.map(task =>
        this.executeSingleTask(task, context)
      );

      const results = await Promise.all(parallelPromises);

      for (let i = 0; i < results.length; i++) {
        const task = uncachedTasks[i];
        const result = results[i];

        individualResults.push(result);

        // Cache successful results
        if (result.success) {
          const cacheKey = `task:${task.agentType}:${this.hashPayload(task.taskPayload)}`;
          this.blackboard.write(cacheKey, result.result, context.agentId, 3600); // 1 hour TTL
        }
      }
    }

    // Synthesize results based on strategy
    const synthesizedResult = this.synthesize(individualResults, synthesisStrategy);

    const totalTime = Date.now() - startTime;
    const successCount = individualResults.filter(r => r.success).length;

    return {
      synthesizedResult,
      individualResults,
      executionMetrics: {
        totalTime,
        successRate: successCount / individualResults.length,
        synthesisStrategy,
      },
    };
  }

  private async executeSingleTask(
    task: ParallelTask,
    context: SkillContext
  ): Promise<ParallelExecutionResult['individualResults'][0]> {
    const taskStart = Date.now();

    try {
      // Build the handoff message
      const handoff: HandoffMessage = {
        handoffId: randomUUID(),
        sourceAgent: context.agentId,
        targetAgent: task.agentType,
        taskType: 'delegate',
        payload: task.taskPayload,
        metadata: {
          priority: 1,
          deadline: Date.now() + CONFIG.defaultTimeout,
          parentTaskId: context.taskId ?? null,
        },
      };

      // Use OpenClaw's internal callSkill to invoke the target agent
      const result = await callSkill(task.agentType, {
        action: 'execute',
        handoff,
        context: {
          blackboardSnapshot: this.blackboard.getSnapshot(),
        },
      });

      return {
        agentType: task.agentType,
        success: true,
        result: result.data,
        executionTime: Date.now() - taskStart,
      };
    } catch (error) {
      return {
        agentType: task.agentType,
        success: false,
        result: {
          error: error instanceof Error ? error.message : 'Unknown error',
          recoverable: true,
        },
        executionTime: Date.now() - taskStart,
      };
    }
  }

  private synthesize(
    results: ParallelExecutionResult['individualResults'],
    strategy: SynthesisStrategy
  ): unknown {
    const successfulResults = results.filter(r => r.success);

    if (successfulResults.length === 0) {
      return {
        error: 'All parallel tasks failed',
        individualErrors: results.map(r => ({
          agent: r.agentType,
          error: r.result,
        })),
      };
    }

    switch (strategy) {
      case 'merge':
        // Combine all results into a unified object
        return {
          merged: true,
          contributions: successfulResults.map(r => ({
            source: r.agentType,
            data: r.result,
          })),
          summary: this.generateMergeSummary(successfulResults),
        };

      case 'vote':
        // Return the result with highest "confidence" (simplified: most data)
        const scored = successfulResults.map(r => ({
          result: r,
          score: JSON.stringify(r.result).length,
        }));
        scored.sort((a, b) => b.score - a.score);
        return {
          voted: true,
          winner: scored[0].result.agentType,
          result: scored[0].result.result,
        };

      case 'chain':
        // Results should already be ordered; return the final one
        return {
          chained: true,
          finalResult: successfulResults[successfulResults.length - 1].result,
          chainLength: successfulResults.length,
        };

      case 'first-success':
        // Return the first successful result
        return {
          firstSuccess: true,
          source: successfulResults[0].agentType,
          result: successfulResults[0].result,
        };

      default:
        return successfulResults.map(r => r.result);
    }
  }

  private generateMergeSummary(results: ParallelExecutionResult['individualResults']): string {
    const agents = results.map(r => r.agentType).join(', ');
    return `Synthesized from ${results.length} agents: ${agents}`;
  }

  private hashPayload(payload: TaskPayload): string {
    // Simple hash for cache key generation
    const str = JSON.stringify(payload);
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }
}

// ============================================================================
// SWARM ORCHESTRATOR - MAIN SKILL IMPLEMENTATION
// ============================================================================

export class SwarmOrchestrator implements OpenClawSkill {
  name = 'SwarmOrchestrator';
  version = '1.0.0';

  private blackboard: SharedBlackboard;
  private authGuardian: AuthGuardian;
  private taskDecomposer: TaskDecomposer;
  private agentRegistry: Map<string, AgentStatus> = new Map();

  constructor(workspacePath: string = process.cwd()) {
    this.blackboard = new SharedBlackboard(workspacePath);
    this.authGuardian = new AuthGuardian();
    this.taskDecomposer = new TaskDecomposer(this.blackboard, this.authGuardian);
  }

  /**
   * Main entry point for the skill
   */
  async execute(action: string, params: Record<string, unknown>, context: SkillContext): Promise<SkillResult> {
    const traceId = randomUUID();

    if (CONFIG.enableTracing) {
      this.blackboard.write(`trace:${traceId}`, {
        action,
        params,
        startTime: new Date().toISOString(),
      }, context.agentId);
    }

    try {
      switch (action) {
        case 'delegate_task':
          return await this.delegateTask(params, context);

        case 'query_swarm_state':
          return await this.querySwarmState(params);

        case 'spawn_parallel_agents':
          return await this.spawnParallelAgents(params, context);

        case 'request_permission':
          return await this.handlePermissionRequest(params, context);

        case 'update_blackboard':
          return this.handleBlackboardUpdate(params, context);

        default:
          return {
            success: false,
            error: {
              code: 'UNKNOWN_ACTION',
              message: `Unknown action: ${action}`,
              recoverable: false,
            },
          };
      }
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'EXECUTION_ERROR',
          message: error instanceof Error ? error.message : 'Unknown error',
          recoverable: true,
          trace: { traceId, action },
        },
      };
    }
  }

  // -------------------------------------------------------------------------
  // CAPABILITY: delegate_task
  // -------------------------------------------------------------------------

  private async delegateTask(params: Record<string, unknown>, context: SkillContext): Promise<SkillResult> {
    const targetAgent = params.targetAgent as string;
    const taskPayload = params.taskPayload as TaskPayload;
    const priority = (params.priority as string) ?? 'normal';
    const timeout = (params.timeout as number) ?? CONFIG.defaultTimeout;
    const requiresAuth = (params.requiresAuth as boolean) ?? false;

    // Check permission wall if required
    if (requiresAuth) {
      const authResult = await this.authGuardian.requestPermission(
        context.agentId,
        'EXTERNAL_SERVICE',
        `Delegating task to ${targetAgent}: ${taskPayload.instruction}`,
        'delegate'
      );

      if (!authResult.granted) {
        return {
          success: false,
          error: {
            code: 'AUTH_DENIED',
            message: `Permission denied: ${authResult.reason}`,
            recoverable: true,
            suggestedAction: 'Provide more specific justification or narrow scope',
          },
        };
      }
    }

    // Check blackboard for existing work
    const cacheKey = `task:${targetAgent}:${JSON.stringify(taskPayload).slice(0, 50)}`;
    const existingWork = this.blackboard.read(cacheKey);
    if (existingWork) {
      return {
        success: true,
        data: {
          taskId: 'cached',
          status: 'completed',
          result: existingWork.value,
          agentTrace: ['blackboard-cache'],
          fromCache: true,
        },
      };
    }

    // Build handoff message
    const handoff: HandoffMessage = {
      handoffId: randomUUID(),
      sourceAgent: context.agentId,
      targetAgent,
      taskType: 'delegate',
      payload: taskPayload,
      metadata: {
        priority: this.priorityToNumber(priority),
        deadline: Date.now() + timeout,
        parentTaskId: context.taskId ?? null,
      },
    };

    // Execute via callSkill
    try {
      const result = await Promise.race([
        callSkill(targetAgent, {
          action: 'execute',
          handoff,
        }),
        this.timeoutPromise(timeout),
      ]);

      // Cache result
      this.blackboard.write(cacheKey, result, context.agentId, 1800); // 30 min TTL

      return {
        success: true,
        data: {
          taskId: handoff.handoffId,
          status: 'completed',
          result,
          agentTrace: [context.agentId, targetAgent],
        },
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'DELEGATION_FAILED',
          message: error instanceof Error ? error.message : 'Task delegation failed',
          recoverable: true,
        },
      };
    }
  }

  // -------------------------------------------------------------------------
  // CAPABILITY: query_swarm_state
  // -------------------------------------------------------------------------

  private async querySwarmState(params: Record<string, unknown>): Promise<SkillResult> {
    const scope = (params.scope as string) ?? 'all';
    const agentFilter = params.agentFilter as string[] | undefined;
    const includeHistory = (params.includeHistory as boolean) ?? false;

    const state: Partial<SwarmState> = {
      timestamp: new Date().toISOString(),
    };

    if (scope === 'all' || scope === 'agents') {
      let agents = Array.from(this.agentRegistry.values());
      if (agentFilter) {
        agents = agents.filter(a => agentFilter.includes(a.agentId));
      }
      state.activeAgents = agents;
    }

    if (scope === 'all' || scope === 'blackboard') {
      state.blackboardSnapshot = this.blackboard.getSnapshot();
    }

    if (scope === 'all' || scope === 'permissions') {
      state.permissionGrants = this.authGuardian.getActiveGrants();
    }

    if (scope === 'all' || scope === 'tasks') {
      // Extract tasks from blackboard
      const snapshot = this.blackboard.getSnapshot();
      state.pendingTasks = Object.entries(snapshot)
        .filter(([key]) => key.startsWith('task:'))
        .map(([, entry]) => ({
          taskId: entry.key,
          agentId: entry.sourceAgent,
          status: 'in_progress' as const,
          startedAt: entry.timestamp,
          description: String(entry.value),
        }));
    }

    return {
      success: true,
      data: state,
    };
  }

  // -------------------------------------------------------------------------
  // CAPABILITY: spawn_parallel_agents
  // -------------------------------------------------------------------------

  private async spawnParallelAgents(
    params: Record<string, unknown>,
    context: SkillContext
  ): Promise<SkillResult> {
    const tasks = params.tasks as ParallelTask[];
    const synthesisStrategy = (params.synthesisStrategy as SynthesisStrategy) ?? 'merge';

    if (!tasks || !Array.isArray(tasks) || tasks.length === 0) {
      return {
        success: false,
        error: {
          code: 'INVALID_PARAMS',
          message: 'Tasks array is required and must not be empty',
          recoverable: false,
        },
      };
    }

    try {
      const result = await this.taskDecomposer.executeParallel(tasks, synthesisStrategy, context);

      return {
        success: true,
        data: result,
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'PARALLEL_EXECUTION_FAILED',
          message: error instanceof Error ? error.message : 'Parallel execution failed',
          recoverable: true,
        },
      };
    }
  }

  // -------------------------------------------------------------------------
  // CAPABILITY: request_permission
  // -------------------------------------------------------------------------

  private async handlePermissionRequest(
    params: Record<string, unknown>,
    context: SkillContext
  ): Promise<SkillResult> {
    const resourceType = params.resourceType as 'SAP_API' | 'FINANCIAL_API' | 'EXTERNAL_SERVICE' | 'DATA_EXPORT';
    const justification = params.justification as string;
    const scope = params.scope as string | undefined;

    if (!resourceType || !justification) {
      return {
        success: false,
        error: {
          code: 'INVALID_PARAMS',
          message: 'resourceType and justification are required',
          recoverable: false,
        },
      };
    }

    const grant = await this.authGuardian.requestPermission(
      context.agentId,
      resourceType,
      justification,
      scope
    );

    return {
      success: grant.granted,
      data: grant,
    };
  }

  // -------------------------------------------------------------------------
  // CAPABILITY: update_blackboard
  // -------------------------------------------------------------------------

  private handleBlackboardUpdate(
    params: Record<string, unknown>,
    context: SkillContext
  ): SkillResult {
    const key = params.key as string;
    const value = params.value;
    const ttl = params.ttl as number | undefined;

    if (!key || value === undefined) {
      return {
        success: false,
        error: {
          code: 'INVALID_PARAMS',
          message: 'key and value are required',
          recoverable: false,
        },
      };
    }

    const previousValue = this.blackboard.read(key)?.value ?? null;
    this.blackboard.write(key, value, context.agentId, ttl);

    return {
      success: true,
      data: {
        success: true,
        previousValue,
      },
    };
  }

  // -------------------------------------------------------------------------
  // UTILITY METHODS
  // -------------------------------------------------------------------------

  private priorityToNumber(priority: string): number {
    const map: Record<string, number> = {
      low: 0,
      normal: 1,
      high: 2,
      critical: 3,
    };
    return map[priority] ?? 1;
  }

  private timeoutPromise(ms: number): Promise<never> {
    return new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`Operation timed out after ${ms}ms`)), ms);
    });
  }

  /**
   * Register an agent with the swarm
   */
  registerAgent(agentId: string, status: AgentStatus['status'] = 'available'): void {
    this.agentRegistry.set(agentId, {
      agentId,
      status,
      currentTask: null,
      lastHeartbeat: new Date().toISOString(),
    });
  }

  /**
   * Update agent status
   */
  updateAgentStatus(agentId: string, status: AgentStatus['status'], currentTask?: string): void {
    const existing = this.agentRegistry.get(agentId);
    if (existing) {
      existing.status = status;
      existing.currentTask = currentTask ?? null;
      existing.lastHeartbeat = new Date().toISOString();
    }
  }
}

// ============================================================================
// EXPORTS & MODULE INITIALIZATION
// ============================================================================

// Default export for OpenClaw skill loader
export default SwarmOrchestrator;

// Named exports for direct usage
export { SharedBlackboard, AuthGuardian, TaskDecomposer };

// Type exports
export type {
  TaskPayload,
  HandoffMessage,
  PermissionGrant,
  SwarmState,
  AgentStatus,
  ParallelTask,
  ParallelExecutionResult,
  SynthesisStrategy,
};

/**
 * Factory function for creating a configured SwarmOrchestrator instance
 */
export function createSwarmOrchestrator(config?: Partial<typeof CONFIG>): SwarmOrchestrator {
  if (config) {
    Object.assign(CONFIG, config);
  }
  return new SwarmOrchestrator();
}
