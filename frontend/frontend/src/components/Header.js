import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
export function Header({ title, description, actions }) {
    return (_jsxs("header", { className: "internal-header", children: [_jsxs("div", { children: [_jsx("div", { className: "internal-header__eyebrow", children: "TRINETRA / SECURITY OPERATIONS" }), _jsx("h1", { children: title }), description && _jsx("p", { children: description })] }), actions && _jsx("div", { children: actions })] }));
}
