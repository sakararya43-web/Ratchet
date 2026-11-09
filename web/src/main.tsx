import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import { chooseMode } from './demo/mode';
import './index.css';

// Live when a RATCHET core answers; otherwise the in-browser demo exchange.
void chooseMode().finally(() => {
  ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
});
