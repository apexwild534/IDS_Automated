import React, { useEffect, useState } from 'react';
import './Rules.css';
import useApi from '../hooks/useApi'; // Adjust path if needed
import { useNavigate } from 'react-router-dom'; // Import useNavigate for navigation

function Rules() {
    const { data: rulesData, loading, error, fetchData } = useApi();
    const [rules, setRules] = useState([]);
    const [showRulesList, setShowRulesList] = useState(false);
    const [comingSoonMessage, setComingSoonMessage] = useState('');
    const [activeButton, setActiveButton] = useState(null);
    const navigate = useNavigate(); // Initialize useNavigate

    useEffect(() => {
        fetchData('/rules'); // Fetch rules from the /rules endpoint
    }, [fetchData]);

    useEffect(() => {
        if (rulesData) {
            setRules(rulesData);
        }
    }, [rulesData]);

    const handleViewClick = () => {
        setShowRulesList(true);
        setComingSoonMessage('');
        setActiveButton('view');
    };

    const handleCreateClick = () => {
        setShowRulesList(false);
        setComingSoonMessage('Coming Soon!');
        setActiveButton('create');
    };

    const handleEditClick = () => {
        setShowRulesList(false);
        setComingSoonMessage('Coming Soon!');
        setActiveButton('edit');
    };

    const handleDeleteClick = () => {
        setShowRulesList(false);
        setComingSoonMessage('Coming Soon!');
        setActiveButton('delete');
    };

    if (loading) {
        return <div className="rules-container">Loading rules...</div>;
    }

    if (error) {
        return <div className="rules-container">Error loading rules: {error}</div>;
    }

    return (
        <div className="rules-container">
            <h2 className="rules-title">Security Rules</h2>
            <div className="button-container">
                <button
                    className={`action-button ${activeButton === 'view' ? 'active' : ''}`}
                    onClick={handleViewClick}
                >
                    View Rules
                </button>
                <button
                    className={`action-button ${activeButton === 'create' ? 'active' : ''}`}
                    onClick={handleCreateClick}
                >
                    Create Rule
                </button>
                <button
                    className={`action-button ${activeButton === 'edit' ? 'active' : ''}`}
                    onClick={handleEditClick}
                >
                    Edit Rule
                </button>
                <button
                    className={`action-button ${activeButton === 'delete' ? 'active' : ''}`}
                    onClick={handleDeleteClick}
                >
                    Delete Rule
                </button>
            </div>

            {comingSoonMessage && <p className="coming-soon-message">{comingSoonMessage}</p>}

            {showRulesList && (
                <>
                    <h2>Existing Rules</h2>
                    {rules.length === 0 ? (
                        <p>No rules defined.</p>
                    ) : (
                        <ul className="rules-list">
                            {rules.map(rule => (
                                <li key={rule.id} className="rule-item">
                                    <div className="rule-info">
                                        <div>
                                            <div className="rule-label">Rule ID:</div>
                                            <div className="rule-value">{rule.id}</div>
                                        </div>
                                        <div>
                                            <div className="rule-label">Name:</div>
                                            <div className="rule-value">{rule.name}</div>
                                        </div>
                                        <div>
                                            <div className="rule-label">Description:</div>
                                            <div className="rule-value">{rule.description}</div>
                                        </div>
                                        {/* Add more rule details here if needed */}
                                    </div>
                                    <div className="rule-actions">
                                        <button className="view-button" onClick={() => navigate(`/rules/${rule.id}`)}>View</button>
                                    </div>
                                </li>
                            ))}
                        </ul>
                    )}
                    <button onClick={() => setShowRulesList(false)}>Back to Menu</button>
                </>
            )}
        </div>
    );
}

export default Rules;