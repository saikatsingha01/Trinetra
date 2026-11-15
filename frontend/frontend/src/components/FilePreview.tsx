/* ==========================================================================
   FilePreview — the selected-file state of the upload card.
   Confirms what will be sent, and offers the way back out.
   ========================================================================== */

import { formatBytes } from '../lib/format';
import { IconCheck, IconFile, IconTrash } from './icons';
import { Button } from './primitives';

export function FilePreview({
  file,
  onRemove,
  busy = false,
}: {
  file: File;
  onRemove: () => void;
  busy?: boolean;
}) {
  return (
    <div className="settle rounded-lg border border-line bg-panel">
      <div className="flex items-start gap-4 px-6 py-6">
        <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-md border border-line-strong bg-inset text-ink-2">
          <IconFile size={19} />
        </span>

        <div className="min-w-0 flex-1">
          <p className="datum text-[13.5px] leading-snug text-ink">{file.name}</p>
          <p className="mt-1 flex items-center gap-2 text-[12px] text-ink-3">
            <span className="tabular">{formatBytes(file.size)}</span>
          </p>
          <p className="mt-3 inline-flex items-center gap-1.5 text-[12.5px] font-medium text-low">
            <IconCheck size={14} />
            Ready for analysis
          </p>
        </div>

        <Button
          variant="ghost"
          size="sm"
          onClick={onRemove}
          disabled={busy}
          aria-label={`Remove ${file.name}`}
        >
          <IconTrash size={13} />
          Remove
        </Button>
      </div>
    </div>
  );
}
