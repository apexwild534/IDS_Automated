import React, { useEffect, useState } from 'react';
import './Alerts.css';
import useApi from '../hooks/useApi'; // Adjust the path if needed

function Alerts() {
    const { data: alertsData, loading, error, fetchData } = useApi();
    const [alerts, setAlerts] = useState([]);

    useEffect(() => {
        fetchData('/alerts'); // Call the /alerts endpoint when the component mounts
    }, [fetchData]);

    useEffect(() => {
        if (alertsData) {
            setAlerts(alertsData); // Directly set alerts state with the fetched data
        }
    }, [alertsData]);

    if (loading) {
        return <div className="alerts-container">Loading alerts...</div>;
    }

    if (error) {
        return <div className="alerts-container">Error loading alerts: {error}</div>;
    }

    return (
        <div className="alerts-container">
            <h2 className="alerts-title">Active Alerts</h2>
            {alerts.length === 0 ? (
                <p>No alerts currently active.</p>
            ) : (
                <ul className="alert-list">
                    {alerts.map(alert => (
                        <li key={alert.id} className="alert-item">
                            <div className="alert-label">Severity:</div>
                            <div className={`alert-value alert-severity ${alert.severity.toLowerCase()}`}>{alert.severity}</div>
                            <div className="alert-label">Timestamp:</div>
                            <div className="alert-value alert-timestamp">{new Date(alert.timestamp).toLocaleString()}</div>
                            {alert.source_ip && <>
                                <div className="alert-label">Source IP:</div>
                                <div className="alert-value">{alert.source_ip}</div>
                            </>}
                            {alert.destination_ip && <>
                                <div className="alert-label">Destination IP:</div>
                                <div className="alert-value">{alert.destination_ip}</div>
                            </>}
                            {alert.description && <>
                                <div className="alert-label">Description:</div>
                                <div className="alert-value alert-description">{alert.description}</div>
                            </>}
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
}

export default Alerts;