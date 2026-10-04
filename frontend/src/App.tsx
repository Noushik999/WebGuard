import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { isAuthed } from './api';
import Login from './pages/Login';
import DashboardPage from './pages/Dashboard';
import { TargetsPage, TargetDetailPage } from './pages/Targets';
import { AssessmentPage, HistoryPage } from './pages/Assessment';
import FindingPage from './pages/Finding';
import ComparePage from './pages/Compare';
import DemoPage from './pages/Demo';

function Guard({ children }: { children: JSX.Element }) {
  return isAuthed() ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<Guard><DashboardPage /></Guard>} />
        <Route path="/targets" element={<Guard><TargetsPage /></Guard>} />
        <Route path="/targets/:id" element={<Guard><TargetDetailPage /></Guard>} />
        <Route path="/assessments" element={<Guard><HistoryPage /></Guard>} />
        <Route path="/assessments/:id" element={<Guard><AssessmentPage /></Guard>} />
        <Route path="/findings/:id" element={<Guard><FindingPage /></Guard>} />
        <Route path="/compare/:aId/:bId" element={<Guard><ComparePage /></Guard>} />
        <Route path="/demo" element={<Guard><DemoPage /></Guard>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
