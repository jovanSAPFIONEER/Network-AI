/**
 * Type declarations for openclaw-core
 * This is a stub module for the OpenClaw framework
 */

declare module 'openclaw-core' {
  /**
   * Base interface for all OpenClaw skills
   */
  export interface OpenClawSkill {
    name: string;
    version: string;
    execute(
      action: string,
      params: Record<string, unknown>,
      context: SkillContext
    ): Promise<SkillResult>;
  }

  /**
   * Context provided to skill execution
   */
  export interface SkillContext {
    agentId: string;
    taskId?: string;
    sessionId?: string;
    metadata?: Record<string, unknown>;
  }

  /**
   * Result returned from skill execution
   */
  export interface SkillResult {
    success: boolean;
    data?: unknown;
    error?: {
      code: string;
      message: string;
      recoverable: boolean;
      suggestedAction?: string;
      trace?: Record<string, unknown>;
    };
  }

  /**
   * Call another skill within the OpenClaw ecosystem
   */
  export function callSkill(
    skillName: string,
    params: Record<string, unknown>
  ): Promise<SkillResult>;
}
