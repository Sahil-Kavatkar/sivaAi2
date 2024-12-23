import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom"; // Updated import for React Router v6
import { motion } from "framer-motion";

const AdminDash = () => {
    const [profile, setProfile] = useState(null);
    const [error, setError] = useState(null);
    const [email, setEmail] = useState(""); // State for manual email input
    const [excelFile, setExcelFile] = useState(null);
    const navigate = useNavigate(); // Use useNavigate instead of useHistory

    useEffect(() => {
        const fetchProfile = async () => {
            try {
                const response = await fetch("http://localhost:8080/adminprofile", {
                    method: "GET",
                    credentials: "include", // Important to include cookies
                });

                console.log('Profile fetch response:', response); // Log response

                if (response.status === 401) {
					console.log("not working");
                    // Handle OTP or authentication failure
                    navigate("/admin/signup"); // Updated navigation method
                    return;
                }

                if (!response.ok) {
                    throw new Error("Failed to fetch profile.");
                }

                const data = await response.json();
                console.log('Profile data:', data); // Log profile data
                setProfile(data.user);
            } catch (error) {
                setError(error.message);
                console.log('Error fetching profile:', error); // Log error
            }
        };

        fetchProfile();
    }, [navigate]); // Include navigate in the dependency array
    
	const handleLogout = async () => {
        try {
            const response = await fetch("http://localhost:8080/adminlogout", {
                method: "GET",
                credentials: "include", // Include credentials for session handling
            });

            if (response.ok) {
                navigate("/admin/login"); // Redirect to login page after successful logout
                console.log("Logged out")
            } else {
                console.error("Failed to log out.");
            }
            const cookies = document.cookie;
            console.log("Cookies after logout attempt:", cookies);
        } catch (err) {
            console.error("Error during logout:", err);
        }
    };

    const handleSingleEmailSubmit = async () => {
        if (!email) {
          alert("Please enter an email");
          return;
        }
    
        try {
          const response = await fetch("http://localhost:8080/addSingleEmail", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ email }),
            credentials: "include",
          });
    
          if (response.ok) {
            alert("Email added successfully!");
            setEmail(""); // Clear input field
          } else {
            alert("Failed to add email.");
          }
        } catch (err) {
          alert("Error: " + err.message);
        }
      };
    
      const handleExcelFileSubmit = async () => {
        if (!excelFile) {
          alert("Please upload an Excel file");
          return;
        }
    
        const formData = new FormData();
        formData.append("file", excelFile);
    
        try {
          const response = await fetch("http://localhost:8080/addExcelFile", {
            method: "POST",
            body: formData,
            credentials: "include",
          });
    
          if (response.ok) {
            alert("Excel file processed successfully.");
            setExcelFile(null); // Clear file input
          } else {
            alert("Failed to process Excel file.");
          }
        } catch (err) {
          alert("Error: " + err.message);
        }
      };
	
    if (error) {
        return <div>{`Error: ${error}`}</div>;
    }

    if (!profile) {
        return <div>Loading...</div>;
    }

    return (
        <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            transition={{ duration: 0.5 }}
            className="max-w-md w-full mx-auto mt-10 p-8 bg-gray-900 bg-opacity-80 backdrop-filter backdrop-blur-lg rounded-xl shadow-2xl border border-gray-800"
        >
            <h2 className="text-3xl font-bold mb-6 text-center bg-gradient-to-r from-green-400 to-emerald-600 text-transparent bg-clip-text">
                Dashboard
            </h2>
            <div className="space-y-6">
                <motion.div
                    className="p-4 bg-gray-800 bg-opacity-50 rounded-lg border border-gray-700"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.2 }}
                >
                    <h3 className="text-xl font-semibold text-green-400 mb-3">Profile Information</h3>
                    <p className="text-gray-300">Name: {profile.displayName}</p>
                    <p className="text-gray-300">Email: {profile.email}</p>
                </motion.div>
                <motion.div
                    className="p-4 bg-gray-800 bg-opacity-50 rounded-lg border border-gray-700"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.4 }}
                >
                    <h3 className="text-xl font-semibold text-green-400 mb-3">Account Activity</h3>
                    <p className="text-gray-300">
                        <span className="font-bold">Joined: </span>
                        {new Date(profile.createdAt).toLocaleDateString("en-US", {
                            year: "numeric",
                            month: "long",
                            day: "numeric",
                        })}
                    </p>
                    <p className="text-gray-300">
                        <span className="font-bold">Last Login: </span>
                        {new Date(profile.organizationId).toLocaleString()}
                    </p>
                </motion.div>
                <motion.div
                    className="p-4 bg-gray-800 bg-opacity-50 rounded-lg border border-gray-700"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.2 }}
                    >
                    <h3 className="text-xl font-semibold text-green-400 mb-3">Add Single Email</h3>
                    <input
                        type="email"
                        placeholder="Enter email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        className="w-full p-2 border border-gray-700 rounded-md"
                    />
                    <button
                        onClick={handleSingleEmailSubmit}
                        className="mt-2 w-full bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 rounded-lg focus:outline-none focus:ring focus:ring-blue-300"
                    >
                        Submit
                    </button>
                    </motion.div>

                        {/* Section 2 - Excel Upload */}
                        <motion.div
                        className="p-4 bg-gray-800 bg-opacity-50 rounded-lg border border-gray-700"
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.4 }}
                        >
                        <h3 className="text-xl font-semibold text-green-400 mb-3">Upload Excel for Bulk Addition</h3>
                        <input
                            type="file"
                            onChange={(e) => setExcelFile(e.target.files[0])}
                            className="w-full p-2 border border-gray-700 rounded-md"
                        />
                        <button
                            onClick={handleExcelFileSubmit}
                            className="mt-2 w-full bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 rounded-lg focus:outline-none focus:ring focus:ring-blue-300"
                        >
                            Upload
                        </button>
                        </motion.div>
				<button
                    onClick={handleLogout}
                    className="w-full bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-4 rounded-lg focus:outline-none focus:ring focus:ring-red-300"
                >
                    Logout
                </button>
            </div>
        </motion.div>
    );
};

export default AdminDash;
