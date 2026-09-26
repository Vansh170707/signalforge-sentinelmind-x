import { AnimatePresence, motion } from 'motion/react'
import { Route, Routes, useLocation } from 'react-router-dom'
import { EvidenceProvider } from './components/EvidenceDrawer'
import { Layout } from './components/Layout'
import { EmptyState, ease } from './components/ui'
import AlertExplorer from './pages/AlertExplorer'
import CommandCenter from './pages/CommandCenter'
import EvaluationLab from './pages/EvaluationLab'
import IncidentDetail from './pages/IncidentDetail'
import IncidentQueue from './pages/IncidentQueue'
import LiveStream from './pages/LiveStream'
import Settings from './pages/Settings'

export default function App() {
  const location = useLocation()
  return (
    <EvidenceProvider>
      <Layout>
        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.22, ease }}
          >
            <Routes location={location}>
              <Route path="/" element={<CommandCenter />} />
              <Route path="/live" element={<LiveStream />} />
              <Route path="/incidents" element={<IncidentQueue />} />
              <Route path="/incidents/:id" element={<IncidentDetail />} />
              <Route path="/alerts" element={<AlertExplorer />} />
              <Route path="/evaluation" element={<EvaluationLab />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<EmptyState title="Page not found" />} />
            </Routes>
          </motion.div>
        </AnimatePresence>
      </Layout>
    </EvidenceProvider>
  )
}
