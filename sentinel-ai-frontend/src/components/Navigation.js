import React, { useState } from 'react';
import './Navigation.css';
import { useNavigate } from 'react-router-dom';

function Navigation() {
    const [activeButton, setActiveButton] = useState(null);
    const navigate = useNavigate();

    // Warning points to this function:
    const handleRulesClick = () => {
        setActiveButton('rules');
        navigate('/rules');
    };

    const handleAlertsClick = () => {
        setActiveButton('alerts');
        navigate('/alerts');
    };

    const handleStatusClick = () => {
        setActiveButton('status');
        navigate('/status');
    };

    const handlePlaygroundClick = () => {
        setActiveButton('playground');
        navigate('/playground');
    };

    return (
        <nav className="cyber-nav">
            <ul>
                <li>
                    <button
                        className={`cyber-link ${activeButton === 'alerts' ? 'active' : ''}`}
                        onClick={handleAlertsClick}
                    >
                        Alerts
                    </button>
                </li>
                <li>
                    <button
                        className={`cyber-link ${activeButton === 'rules' ? 'active' : ''}`}
                        // It's likely the onClick for Rules is missing or incorrect
                        onClick={handleRulesClick}
                    >
                        Rules
                    </button>
                </li>
                <li>
                    <button
                        className={`cyber-link ${activeButton === 'status' ? 'active' : ''}`}
                        onClick={handleStatusClick}
                    >
                        Status
                    </button>
                </li>
                <li>
                    <button
                        className={`cyber-link ${activeButton === 'playground' ? 'active' : ''}`}
                        onClick={handlePlaygroundClick}
                    >
                        Playground
                    </button>
                </li>
            </ul>
        </nav>
    );
}

export default Navigation;