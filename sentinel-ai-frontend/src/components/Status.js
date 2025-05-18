import React, { useEffect, useState } from 'react';
import './Status.css'; // Create this file in the next step
import useApi from '../hooks/useApi'; // Adjust the path if needed

function Status() {
    const { data: statusData, loading, error, fetchData } = useApi();
    const [status, setStatus] = useState(null); // Status is likely a single object

    useEffect(() => {
        fetchData('/status'); // Fetch status from the /status endpoint
    }, [fetchData]);

    useEffect(() => {
        if (statusData) {
            setStatus(statusData);
        }
    }, [statusData]);

    if (loading) {
        return <div className="status-container">Loading status...</div>;
    }

    if (error) {
        return <div className="status-container">Error loading status: {error}</div>;
    }

    return (
        <div className="status-container">
            <h2 className="status-title">System Status</h2>
            {status ? (
                <div className="status-details">
                    {Object.entries(status).map(([key, value]) => (
                        <div key={key} className="status-item">
                            <div className="status-label">{key}:</div>
                            <div className="status-value">{String(value)}</div>
                        </div>
                    ))}
                </div>
            ) : (
                <p>No status information available.</p>
            )}
        </div>
    );
}

export default Status;