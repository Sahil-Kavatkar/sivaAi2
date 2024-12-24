import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom"; // Updated import for React Router v6
import { motion } from "framer-motion";
import Navbar from "../components/Navbar";
import Sidebar from "../components/Sidebar";
import Welcome from "../components/Welcome";
import ChatInput from "../components/ChatInput";
import ParticlesBackground from "../components/ParticlesBackground";

const DashboardPage = () => {
    const [profile, setProfile] = useState(null);
    const [error, setError] = useState(null);
    const navigate = useNavigate(); // Use useNavigate instead of useHistory
    const [darkMode, setDarkMode] = useState(false);
    const [isWelcomeVisible, setIsWelcomeVisible] = useState(true); // State for visibility

    useEffect(() => {
        const fetchProfile = async () => {
            try {
                const response = await fetch("https://siva-ai-hpg2.onrender.com/profile", {
                    method: "GET",
                    credentials: "include", // Important to include cookies
                });

                console.log("Profile fetch response:", response); // Log response

                if (response.status === 401) {
                    console.log("Not working");
                    // Handle OTP or authentication failure
                    navigate("/signup"); // Updated navigation method
                    return;
                }

                if (!response.ok) {
                    throw new Error("Failed to fetch profile.");
                }

                const data = await response.json();
                console.log("Profile data:", data); // Log profile data
                setProfile(data.user);
            } catch (error) {
                setError(error.message);
                console.log("Error fetching profile:", error); // Log error
            }
        };

        fetchProfile();
    }, [navigate]); // Include navigate in the dependency array

    useEffect(() => {
        if (darkMode) {
            document.documentElement.classList.remove("dark");
        } else {
            document.documentElement.classList.add("dark");
        }
    }, [darkMode]);

    const toggleDarkMode = () => {
        setDarkMode(!darkMode);
    };
    
    const handleMessageSent = () => {
        setIsWelcomeVisible(false); // Hide Welcome component when message is sent
    };

    const handleLogout = async () => {
        try {
            const response = await fetch("https://siva-ai-hpg2.onrender.com/logout", {
                method: "GET",
                credentials: "include", // Include credentials for session handling
            });

            if (response.ok) {
                navigate("/login"); // Redirect to login page after successful logout
            } else {
                console.error("Failed to log out.");
            }
        } catch (err) {
            console.error("Error during logout:", err);
        }
    };

    if (error) {
        return <div>{`Error: ${error}`}</div>;
    }

    if (!profile) {
        return <div>Loading...</div>;
    }

    return (
        <div>
            <Navbar />
            <ParticlesBackground />
            <Sidebar darkMode={darkMode} toggleDarkMode={toggleDarkMode} onLogout={handleLogout}/>
            {isWelcomeVisible && <Welcome profile={profile} />} {/* Pass profile as a prop */}
            <ChatInput onMessageSent={handleMessageSent} />
        </div>
    );
};

export default DashboardPage;
