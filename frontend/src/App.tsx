import { Route, Routes } from 'react-router-dom'
import { EvidenceProvider } from './components/EvidenceDrawer'
import { Layout } from './components/Layout'
import { EmptyState } from './components/ui'
import AlertExplorer from './pages/AlertExplorer'
import CommandCenter from './pages/CommandCenter'
import EvaluationLab from './pages/EvaluationLab'
import IncidentDetail from './pages/IncidentDetail'
import IncidentQueue from './pages/IncidentQueue'
import Settings from './pages/Settings'

export default function App() {
  return (
    <EvidenceProvider>
      <Layout>
        <Routes>
          <Route path="/" element={<CommandCenter />} />
          <Route path="/incidents" element={<IncidentQueue />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/alerts" element={<AlertExplorer />} />
          <Route path="/evaluation" element={<EvaluationLab />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<EmptyState title="Page not found" />} />
        </Routes>
      </Layout>
    </EvidenceProvider>
  )
}
