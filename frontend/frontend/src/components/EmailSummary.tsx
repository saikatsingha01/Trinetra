/* ==========================================================================
   EmailSummary — the email as the backend reported it.
   Nothing on this screen was read out of the .eml by the browser.
   ========================================================================== */

import type { EmailMetadata } from '../types/analysis';
import { formatDateTime } from '../lib/format';
import { EmptyNote, Field, Section } from './primitives';

export function EmailSummary({ email }: { email?: EmailMetadata | null }) {
  if (!email) {
    return (
      <Section title="Email">
        <EmptyNote>The response did not include email metadata.</EmptyNote>
      </Section>
    );
  }

  return (
    <Section title="Email">
      <div className="grid gap-5 px-5 py-5 sm:grid-cols-2">
        <Field label="From" value={email.sender} />
        <Field label="To" value={email.recipient} />
        <Field label="Subject" value={email.subject} mono={false} className="sm:col-span-2" />
        <Field label="Date" value={formatDateTime(email.date)} />
        <Field label="Message ID" value={email.message_id} />
      </div>
    </Section>
  );
}
