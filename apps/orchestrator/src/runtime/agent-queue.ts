export type AgentPriority = 1 | 2 | 3 | 4;

interface Waiting {
  priority: AgentPriority;
  order: number;
  resolve: (release: () => void) => void;
  reject: (error: unknown) => void;
  signal: AbortSignal;
  abort: () => void;
}

export class AgentQueue {
  private active = 0;
  private order = 0;
  private waiting: Waiting[] = [];
  readonly maxParallel: number;
  constructor(maxParallel = Number(process.env.CODEX_MAX_PARALLEL || 2)) {
    if (!Number.isSafeInteger(maxParallel) || maxParallel < 1 || maxParallel > 16)
      throw new Error("CODEX_MAX_PARALLEL_INVALID");
    this.maxParallel = maxParallel;
  }
  acquire(priority: AgentPriority, signal: AbortSignal): Promise<() => void> {
    if (signal.aborted) return Promise.reject(signal.reason ?? new Error("aborted"));
    if (this.active < this.maxParallel && this.waiting.length === 0) {
      this.active++;
      return Promise.resolve(this.releaseOnce());
    }
    return new Promise((resolve, reject) => {
      const waiting: Waiting = { priority, order: this.order++, resolve, reject, signal,
        abort: () => {
          this.waiting = this.waiting.filter((item) => item !== waiting);
          reject(signal.reason ?? new Error("aborted"));
        } };
      signal.addEventListener("abort", waiting.abort, { once: true });
      this.waiting.push(waiting);
      this.waiting.sort((left, right) => left.priority - right.priority || left.order - right.order);
    });
  }
  private releaseOnce(): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active--;
      while (this.waiting.length) {
        const next = this.waiting.shift()!;
        next.signal.removeEventListener("abort", next.abort);
        if (next.signal.aborted) { next.reject(next.signal.reason); continue; }
        this.active++;
        next.resolve(this.releaseOnce());
        return;
      }
    };
  }
  state(): { active: number; queued: number } {
    return { active: this.active, queued: this.waiting.length };
  }
}
