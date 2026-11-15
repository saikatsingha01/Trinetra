import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { formatDateTime } from '../lib/format';
import { EmptyNote, Field, Section } from './primitives';
export function EmailSummary({ email }) {
    if (!email) {
        return (_jsx(Section, { title: "Email", children: _jsx(EmptyNote, { children: "The response did not include email metadata." }) }));
    }
    return (_jsx(Section, { title: "Email", children: _jsxs("div", { className: "grid gap-5 px-5 py-5 sm:grid-cols-2", children: [_jsx(Field, { label: "From", value: email.sender }), _jsx(Field, { label: "To", value: email.recipient }), _jsx(Field, { label: "Subject", value: email.subject, mono: false, className: "sm:col-span-2" }), _jsx(Field, { label: "Date", value: formatDateTime(email.date) }), _jsx(Field, { label: "Message ID", value: email.message_id })] }) }));
}
