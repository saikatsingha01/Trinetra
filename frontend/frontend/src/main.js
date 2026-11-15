import { jsx as _jsx } from "react/jsx-runtime";
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { SessionProvider } from './store/session';
import './index.css';
const container = document.getElementById('root');
if (!container)
    throw new Error('#root is missing from index.html');
createRoot(container).render(_jsx(StrictMode, { children: _jsx(BrowserRouter, { children: _jsx(SessionProvider, { children: _jsx(App, {}) }) }) }));
