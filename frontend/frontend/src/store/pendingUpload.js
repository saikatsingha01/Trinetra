/* ==========================================================================
   pendingUpload — a one-slot handoff for a file picked on one screen and
   analysed on another.
   --------------------------------------------------------------------------
   A File cannot go through router state (history entries must be
   serialisable), so it is parked here in module scope for the length of one
   navigation and taken exactly once.
   ========================================================================== */
let pending = null;
export function stagePendingFile(file) {
    pending = file;
}
/** Returns the staged file and clears the slot, so a reload starts clean. */
export function takePendingFile() {
    const file = pending;
    pending = null;
    return file;
}
