import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios'; // Import axios
import './LoginForm.css'; // Make sure you have this CSS file for styling

function LoginForm() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');  // Add error state to display messages
  const navigate = useNavigate();  // Initialize useNavigate for routing

  // handleSubmit function to handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const response = await axios.post('http://localhost:5000/api/admin/login', {
        email,
        password,
      });      

      if (response.data.token) {
        // Store token in localStorage
        localStorage.setItem("authToken", response.data.token);
        // Redirect to profile page or another route
        navigate('/admin-dashboard');  // Redirection vers la page AdminDashboard
      } else {
        // Display error message
        setError(response.data.message);
      }
    } catch (error) {
      console.error('Login error:', error);
      setError('Invalid credentials or server error');
    }
  };

  return (
    <div className="login-container">
      <div className="login-box">
        <h2>AutiLearn</h2> {/* Changed the title */}
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Enter your email"
              required
            />
          </div>

          <div className="form-group">
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              required
            />
          </div>

          <button type="submit">Sign in</button>
        </form>

        {error && <div className="error-message">{error}</div>}  {/* Show error if any */}

        <div className="links">
          <Link to="/forgot-password">Forgot password?</Link>
          <p>
            You don't have an account? <Link to="/user-type">Create an account</Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default LoginForm;
