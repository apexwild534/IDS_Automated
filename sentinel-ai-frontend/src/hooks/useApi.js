// In src/hooks/useApi.js

import { useState, useCallback } from 'react';

function useApi(baseUrl = 'http://localhost:8000') {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const fetchData = useCallback(async (endpoint, method = 'GET', body = null, headers = {}) => {
        setLoading(true);
        setError(null);
        console.log('Fetching:', endpoint);

        try {
            const url = `${baseUrl}${endpoint}`;
            const config = {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    ...headers,
                },
                body: body ? JSON.stringify(body) : null,
            };
            console.log('Request Config:', config);
            const response = await fetch(url, config);
            console.log('Response:', response);

            if (!response.ok) {
                let errorData;
                try {
                    errorData = await response.json();
                } catch (e) {
                    errorData = { detail: `HTTP error! status: ${response.status}` };
                }
                console.error('API Error:', errorData);
                throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
            }

            let responseData;
            try {
                const text = await response.text();
                responseData = JSON.parse(text);
                console.log('Response Data:', responseData);
                setData(responseData);
            } catch (e) {
                console.error("Error parsing JSON response:", e);
                setError("Error parsing data from the server.");
                setLoading(false);
                return;
            }
        } catch (err) {
            console.error('Fetch Error:', err);
            setError(err.message);
        } finally {
            setLoading(false);
            console.log('Loading finished:', loading);
        }
    }, [baseUrl, loading]); // <-- Added 'loading' to the dependency array

    return { data, loading, error, fetchData };
}

export default useApi;