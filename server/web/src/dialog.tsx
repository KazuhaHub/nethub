import { useEffect, useId, useRef, type ReactNode } from "react";
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";

export function NativeDialog({
  open,
  title,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const dialog = ref.current;
    if (open && !dialog?.open) dialog?.showModal();
    if (!open && dialog?.open) dialog.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      className="native-dialog"
      aria-labelledby={titleId}
      onClose={onClose}
      onKeyDown={(event) => {
        if (event.key !== "Tab") return;
        const dialog = ref.current;
        if (!dialog) return;
        const controls = Array.from(
          dialog.querySelectorAll<HTMLElement>(
            'button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), a[href], [tabindex="0"]',
          ),
        );
        const first = controls[0],
          last = controls.at(-1);
        if (!first || !last) {
          event.preventDefault();
          return;
        }
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }}
    >
      <header className="dialog-heading">
        <h2 id={titleId}>{title}</h2>
        <Button
          variant="ghost"
          size="icon"
          aria-label="Close dialog"
          onClick={onClose}
        >
          <X />
        </Button>
      </header>
      {children}
    </dialog>
  );
}
