import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { createBrowserRouter, Link, RouterProvider } from 'react-router-dom';
import '@fontsource/ibm-plex-sans/400.css';
import '@fontsource/ibm-plex-sans/500.css';
import '@fontsource/ibm-plex-sans/600.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import './index.css';
import { Layout } from './components/Layout';
import { DashboardPage } from './pages/Dashboard';
import { InvestigationsPage } from './pages/Investigations';
import { NewInvestigationPage } from './pages/NewInvestigation';
import { InvestigationDetailPage } from './pages/InvestigationDetail';
import { ReportsPage } from './pages/Reports';
import { SettingsPage } from './pages/Settings';
import { Empty } from './components/ui';

const router = createBrowserRouter([
  {
    element: <Layout />,
    children: [
      { path: '/', element: <DashboardPage /> },
      { path: '/investigations', element: <InvestigationsPage /> },
      { path: '/investigations/:id', element: <InvestigationDetailPage /> },
      { path: '/new', element: <NewInvestigationPage /> },
      { path: '/reports', element: <ReportsPage /> },
      { path: '/settings', element: <SettingsPage /> },
      { path: '*', element: <Empty title="Page not found"><Link to="/" className="text-accent">Go to dashboard</Link></Empty> },
    ],
  },
]);

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
