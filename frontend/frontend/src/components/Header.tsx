import type { ReactNode } from 'react';

export function Header({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <header className="internal-header">
      <div>
        <div className="internal-header__eyebrow">TRINETRA / SECURITY OPERATIONS</div>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {actions && <div>{actions}</div>}
    </header>
  );
}
