import { jsx as _jsx } from "react/jsx-runtime";
import { useNavigate } from 'react-router-dom';
import { AnimatedTopDock, PredictiveArcCanvas, SemanticBloom } from '@designcodeio/threeui';
import '@designcodeio/threeui/style.css';
export function PredictiveRibbon({ className = '' }) {
    return (_jsx("div", { className: `trinetra-ribbon ${className}`, "aria-hidden": "true", children: _jsx(PredictiveArcCanvas, { variant: "ribbon-field", speed: 1.00, pointerAmount: 1.00, smoothing: 0.035, hue: 0, saturation: 1.00, brightness: 1.00, opacity: 1.00 }) }));
}
const ROUTES = ['/', '/analyze', '/cases', '/intel', '/settings'];
export function TrinetraDock() {
    const navigate = useNavigate();
    function onClick(event) {
        const button = event.target.closest('button');
        if (!button)
            return;
        const buttons = Array.from(event.currentTarget.querySelectorAll('button'));
        const index = buttons.indexOf(button);
        if (index >= 0 && index < ROUTES.length)
            navigate(ROUTES[index]);
    }
    return (_jsx("div", { className: "trinetra-dock", onClick: onClick, children: _jsx(AnimatedTopDock, { variant: "glass", particles: 22, thickness: 0.115, dispersion: 0.050, specular: 0.85, rim: 0.50, drift: 1.00, proximity: 44, heightGrowth: 20, drop: 11.0 }) }));
}
export function TrinetraBloom() {
    return (_jsx("div", { className: "trinetra-bloom", "aria-hidden": "true", children: _jsx(SemanticBloom, { mode: "light", text: "TRINETRA", size: 1.00, opacity: 1.00 }) }));
}
