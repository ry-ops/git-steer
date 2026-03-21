import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import RepoList from './pages/RepoList';
import ScanResults from './pages/ScanResults';
import CveDetail from './pages/CveDetail';

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/repos" element={<RepoList />} />
        <Route path="/repos/:owner/:repo" element={<ScanResults />} />
        <Route path="/cve/:cveId" element={<CveDetail />} />
      </Routes>
    </Layout>
  );
}
