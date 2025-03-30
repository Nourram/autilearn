import React from 'react'; 
import LoginForm from './components/login/LoginForm'; // Ajuste le chemin si nécessaire
import UserTypeSelection from './components/Usertype/UserTypeSelection';
import ForgotPassword from './components/Password/ForgotPassword'; // Importation du ForgotPassword
import ParentForm from './components/users/ParentForm';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import PedagogueForm from './components/users/PedagogueForm';
import HealthProfessionalForm from './components/users/HealthProfessionalForm';
import AdminDashboard from './components/AdminDashboard';  // Ajoutez cette ligne pour AdminDashboard

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<LoginForm />} />
        <Route path="/user-type" element={<UserTypeSelection />} />
        <Route path="/parent-form" element={<ParentForm />} />
        <Route path="/forgot-password" element={<ForgotPassword />} /> {/* Ajout de la route ForgotPassword */}
        <Route path="/pédagogue-form" element={<PedagogueForm />} />
        <Route path="/health-professional-form" element={<HealthProfessionalForm />} />
        <Route path="/admin-dashboard" element={<AdminDashboard />} />  {/* Ajoutez cette ligne pour AdminDashboard */}
      </Routes>
    </Router>
  );
}

export default App;
