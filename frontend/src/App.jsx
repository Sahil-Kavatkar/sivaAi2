import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Header from './components/Header';
import Hero from './components/Hero';
import Features from './components/Features';
import Process from './components/Process';
import CodeDemo from './components/CodeDemo';
import Pricing from './components/Pricing';
import Footer from './components/Footer';
// import SparkleEffect from './components/SparkleEffect';
import Mentorship from './pages/Mentorship'; // Import Mentorship page
import Contact from './pages/Contact';
import Navbar from "./components/Navbar";
import Sidebar from "./components/Sidebar";
import Welcome from "./components/Welcome";
import ChatHistory from "./components/ChatHistory";
import ChatInput from "./components/ChatInput";
import KnowledgeBase from "./components/KnowledgeBase";
import DataManagement from "./components/DataManagement";
import Landing from './pages/Landing';
import WelcomePage from './pages/WelcomePage';
import KnowledgePage from './pages/KnowledgePage';
import DataManagementPage from './pages/DatamanagemnentPage';
import ParticlesBackground from './components/ParticlesBackground';

import SignUpPage from "./pages/SignUpPage";
import LoginPage from "./pages/LoginPage";
import EmailVerificationPage from "./pages/EmailVerificationPage";
import DashboardPage from "./pages/DashboardPage";
import ForgotPasswordPage from "./pages/ForgotPasswordPage";
import ResetPasswordPage from "./pages/ResetPasswordPage";

import AdminSignUpPage from "./pages/AdminSignUpPage";
import AdminLoginPage from "./pages/AdminLoginPage"
import AdminOTPVerificationPage from "./pages/AdminOTPVerificationPage";
import AdminDash from "./pages/AdminDash";


function App() {
  

  return (
    <Router>
      <div className="min-h-screen bg-dark">
        
        <main>
          
          <Routes>
            {/* The home page and other sections */}
            <Route path='/' element ={<Landing></Landing>} />
            {/* The contact page */}
            <Route path="/dash" element={<DashboardPage />} />
            <Route path="/signup" element={<SignUpPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/verify-email" element={<EmailVerificationPage />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
            <Route path="/reset-password/:token" element={<ResetPasswordPage />} />
            <Route path="/admin/signup" element={<AdminSignUpPage />} />
            <Route path="/admin/login" element={<AdminLoginPage />} />
            <Route path="/admin/verify-otp" element={<AdminOTPVerificationPage />} />
            <Route path="/admin/dash" element={<AdminDash />} />
            <Route path="/contact" element={<><Header /><Contact /><Footer /></>} />
            {/* The mentorship page */}
            <Route path="/mentorship" element={<><Header /><Mentorship /><Footer /></>} />
            <Route path="/welcome" element={<WelcomePage></WelcomePage>} />
            <Route path="/knowledge-hub" element={<KnowledgePage></KnowledgePage>} />
            <Route path="/datamanagement" element={<DataManagementPage></DataManagementPage>} />
          </Routes>
        </main>
        
      </div>
    </Router>
  );
}

export default App;
