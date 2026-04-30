import React from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Header from './components/Header'
import TopNav from './components/TopNav'
import Dashboard from './pages/Dashboard'
import ThreatFeeds from './pages/ThreatFeeds'
import Actors from './pages/Actors'
import IOCHunt from './pages/IOCHunt'
import ATTACKMatrix from './pages/ATTACKMatrix'
import CVETracker from './pages/CVETracker'
import DarkWeb from './pages/DarkWeb'
import Watchlist from './pages/Watchlist'
import AIAnalyst from './pages/AIAnalyst'
import FeedHealth from './pages/FeedHealth'
import Admin from './pages/Admin'

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex flex-col h-screen overflow-hidden bg-navy-950">
        <Header />
        <TopNav />
        <main className="flex-1 overflow-y-auto p-4 lg:p-5">
          <Routes>
            <Route path="/"            element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard"   element={<Dashboard />} />
            <Route path="/feeds"       element={<ThreatFeeds />} />
            <Route path="/actors"      element={<Actors />} />
            <Route path="/ioc-hunt"    element={<IOCHunt />} />
            <Route path="/attack"      element={<ATTACKMatrix />} />
            <Route path="/cves"        element={<CVETracker />} />
            <Route path="/darkweb"     element={<DarkWeb />} />
            <Route path="/watchlist"   element={<Watchlist />} />
            <Route path="/ai-analyst"  element={<AIAnalyst />} />
            <Route path="/feed-health" element={<FeedHealth />} />
            <Route path="/admin"       element={<Admin />} />
            <Route path="*"            element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
