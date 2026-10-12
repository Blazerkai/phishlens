/** Minimal FIFO job queue with bounded concurrency. Keeps analysis load predictable. */
export class JobQueue {
  private running = 0;
  private readonly waiting: (() => Promise<void>)[] = [];

  constructor(private readonly concurrency: number) {}

  push(job: () => Promise<void>): void {
    this.waiting.push(job);
    this.drain();
  }

  get size(): { running: number; waiting: number } {
    return { running: this.running, waiting: this.waiting.length };
  }

  /** Resolves when all queued and running jobs have finished (used by tests and shutdown). */
  async idle(): Promise<void> {
    while (this.running > 0 || this.waiting.length > 0) await new Promise((r) => setTimeout(r, 10));
  }

  private drain(): void {
    while (this.running < this.concurrency && this.waiting.length) {
      const job = this.waiting.shift()!;
      this.running++;
      job()
        .catch(() => {})
        .finally(() => {
          this.running--;
          this.drain();
        });
    }
  }
}
