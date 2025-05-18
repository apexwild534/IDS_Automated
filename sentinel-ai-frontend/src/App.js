import React from 'react';
import logo from './logo.png';
import { Routes, Route } from 'react-router-dom';
import Alerts from './components/Alerts';
import Rules from './components/Rules';
import Status from './components/Status';
import Playground from './components/Playground';
import Navigation from './components/Navigation';
import './App.css';

function App() {
    return (
        <div className="app">
            <header className="cyber-header">
                <div className="logo-container">
                    <img src={logo} alt="Sentinel AI Logo" className="logo-top-left" />
                </div>
                <div className="header-text-container">
                    <h1 className="cyber-title">Sentinel <span className="cyber-title-ai">AI</span></h1>
                    <p className="cyber-subtitle">Automated Security Monitoring</p>
                </div>
            </header>
            <Navigation />
            <main className="cyber-main">
                <Routes>
                    <Route path="/alerts" element={<Alerts />} />
                    <Route path="/rules" element={<Rules />} />
                    <Route path="/status" element={<Status />} />
                    <Route path="/playground" element={<Playground />} />
                    <Route path="/" element={
                        <div className="homepage-container">
                            <h2 className="homepage-title">Welcome to Sentinel AI</h2>
                            <p className="homepage-text">Your intelligent security analysis platform.</p>
                            <div className="homepage-features">
                                <div className="feature-item">Real-time Monitoring</div>
                                <div className="feature-item">Advanced Rule Engine</div>
                                <div className="feature-item">Anomaly Detection</div>
                                <div className="feature-item">Interactive Dashboard</div>
                            </div>
                        </div>
                    } />
                </Routes>
            </main>
            <footer className="cyber-footer">
                <p>&copy; 2025 Sentinel AI</p>
                <p>Kevin Dhankhar</p>
            </footer>
        </div>
    );
}

export default App;