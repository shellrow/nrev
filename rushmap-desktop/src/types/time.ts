// Rust Duration
/* export interface Duration {
  secs: number;
  nanos: number;
} */

export class Duration {
    public secs: number;
    public nanos: number;

    constructor(secs: number, nanos: number) {
        this.secs = secs;
        this.nanos = nanos;
    }

    public as_secs(): number {
        return this.secs;
    }

    public as_millis(): number {
        return this.secs * 1000 + this.nanos / 1000000;
    }

    public as_nanos(): number {
        return this.secs * 1000000000 + this.nanos;
    }
}

// Impl Duration, as_secs, as_millis, as_nanos
export function as_secs(duration: Duration): number {
  return duration.secs;
}

export function as_millis(duration: Duration): number {
  return duration.secs * 1000 + duration.nanos / 1000000;
}

export function as_nanos(duration: Duration): number {
  return duration.secs * 1000000000 + duration.nanos;
}
