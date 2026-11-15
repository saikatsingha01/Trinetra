import type { MouseEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { AnimatedTopDock, PredictiveArcCanvas, SemanticBloom } from '@designcodeio/threeui';
import '@designcodeio/threeui/style.css';

export function PredictiveRibbon({ className = '' }: { className?: string }) {
  return (
    <div className={`trinetra-ribbon ${className}`} aria-hidden="true">
      <PredictiveArcCanvas
        variant="ribbon-field"
        speed={1.00}
        pointerAmount={1.00}
        smoothing={0.035}
        hue={0}
        saturation={1.00}
        brightness={1.00}
        opacity={1.00}
      />
    </div>
  );
}

const ROUTES = ['/', '/analyze', '/cases', '/intel', '/settings'];

export function TrinetraDock() {
  const navigate = useNavigate();
  function onClick(event: MouseEvent<HTMLElement>) {
    const button = (event.target as HTMLElement).closest('button');
    if (!button) return;
    const buttons = Array.from(event.currentTarget.querySelectorAll('button'));
    const index = buttons.indexOf(button);
    if (index >= 0 && index < ROUTES.length) navigate(ROUTES[index]);
  }
  return (
    <div className="trinetra-dock" onClick={onClick}>
      <AnimatedTopDock
        variant="glass"
        particles={22}
        thickness={0.115}
        dispersion={0.050}
        specular={0.85}
        rim={0.50}
        drift={1.00}
        proximity={44}
        heightGrowth={20}
        drop={11.0}
      />
    </div>
  );
}

export function TrinetraBloom() {
  return (
    <div className="trinetra-bloom" aria-hidden="true">
      <SemanticBloom mode="light" text="TRINETRA" size={1.00} opacity={1.00} />
    </div>
  );
}
