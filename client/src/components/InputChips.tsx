import type { InputType } from '@phishlens/shared';
import { INPUT_LABEL } from '../lib/format';

export function InputChips({ types }: { types: InputType[] }) {
  return (
    <div className="mt-0.5 flex flex-wrap gap-1">
      {types.map((t) => (
        <span key={t} className="rounded-[3px] border border-line px-1.5 text-[10.5px] uppercase tracking-wider text-faint">
          {INPUT_LABEL[t]}
        </span>
      ))}
    </div>
  );
}
