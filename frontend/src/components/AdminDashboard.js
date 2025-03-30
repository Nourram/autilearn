import React, { useEffect, useState } from 'react';
import './AdminDashboard.css';  

const AdminDashboard = () => {
  const [statistics, setStatistics] = useState(null);
  const [recentActivities, setRecentActivities] = useState([]);

  useEffect(() => {
    const token = localStorage.getItem("authToken"); // Récupère le token depuis le localStorage

    if (!token) {
      console.log("No token found");
      return;  // Si pas de token, on arrête la requête
    }

    // Fetch statistics from the backend (replace with your actual API URL)
    fetch('http://localhost:5000/api/admin/admin-statistics', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,  // Ajoute le token dans l'en-tête
      }
    })
      .then(response => response.json())
      .then(data => setStatistics(data))
      .catch(error => console.error('Error fetching statistics:', error));

    // Fetch recent activities (replace with your actual API URL)
    fetch('http://localhost:5000/api/admin/recent-activities', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,  // Ajoute le token ici aussi
      }
    })
      .then(response => response.json())
      .then(data => setRecentActivities(data))
      .catch(error => console.error('Error fetching recent activities:', error));
  }, []);

  return (
    <div className="dashboard-container">
      <h1>Admin Dashboard</h1>
      
      {/* Statistics Section */}
      <div className="statistics-section">
        <h2>Statistics</h2>
        {statistics ? (
          <div className="statistics">
            <div className="stat-card">
              <h3>Total Users</h3>
              <p>{statistics.totalUsers}</p>
            </div>
            <div className="stat-card">
              <h3>Total Exercises</h3>
              <p>{statistics.totalExercises}</p>
            </div>
            <div className="stat-card">
              <h3>Active Users</h3>
              <p>{statistics.activeUsers}</p>
            </div>
          </div>
        ) : (
          <p>Loading statistics...</p>
        )}
      </div>
      
      {/* Recent Activities Section */}
      <div className="recent-activities-section">
        <h2>Recent Activities</h2>
        {recentActivities.length > 0 ? (
          <ul className="recent-activities-list">
            {recentActivities.map((activity, index) => (
              <li key={index}>
                <p><strong>{activity.user}</strong> {activity.action} at {activity.timestamp}</p>
              </li>
            ))}
          </ul>
        ) : (
          <p>No recent activities</p>
        )}
      </div>
    </div>
  );
};

export default AdminDashboard;
