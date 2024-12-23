import axios from "axios";
import { motion } from "framer-motion";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import Input from "../components/Input";
import PasswordStrengthMeter from "../components/PasswordStrengthMeter";
import { Loader, Lock, Mail, User, Clipboard } from "lucide-react";
import AuthLayout from './AuthLayout';

const AdminSignUpPage = () => {
    const [name, setName] = useState("");
    const [email, setEmail] = useState("");
    const [organizationId, setOrganizationId] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();

    const handleSignUp = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError(null);

        try {
            console.log("Sending admin signup request...");
            const response = await axios.post("http://localhost:8080/adminsignin", {
                email,
                password,
                name,
                organizationId,
            });

            console.log(response.data.message);
            navigate("/admin/login");
        } catch (err) {
            console.error(err);
            setError(err.response?.data?.error || "An error occurred during admin signup");
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <AuthLayout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        
      >
        <div className="p-8">
          <h2 className="text-4xl font-bold text-white mb-6 text-center">
            Create Account
          </h2>
          <form onSubmit={handleSignUp}>
            {/* Full Name Input */}
            <div className="mb-5">
              <label className="block text-sm font-medium text-gray-400 mb-1">
                Full Name
              </label>
              <Input
                icon={User}
                type="text"
                placeholder="Enter your full name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                required
              />
            </div>

            {/* Email Input */}
            <div className="mb-5">
              <label className="block text-sm font-medium text-gray-400 mb-1">
                Email Address
              </label>
              <Input
                icon={Mail}
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                required
              />
            </div>

            {/* Organization ID Input */}
            <div className="mb-5">
              <label className="block text-sm font-medium text-gray-400 mb-1">
                Organization ID
              </label>
              <Input
                icon={Clipboard}
                type="text"
                placeholder="Organization ID"
                value={organizationId}
                onChange={(e) => setOrganizationId(e.target.value)}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                required
              />
            </div>

            {/* Password Input */}
            <div className="mb-5">
              <label className="block text-sm font-medium text-gray-400 mb-1">
                Password
              </label>
              <Input
                icon={Lock}
                type="password"
                placeholder="Create a password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                required
              />
            </div>

            {/* Error Message */}
            {error && <p className="text-red-500 font-semibold mt-2">{error}</p>}

            {/* Submit Button */}
            <motion.button
              className="w-full py-3 px-4 bg-purple-600 text-white rounded-lg shadow-lg hover:bg-purple-700 transition duration-200"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              type="submit"
              disabled={isLoading}
            >
              {isLoading ? (
                <div className="animate-spin mx-auto w-5 h-5 border-2 border-white border-t-transparent rounded-full"></div>
              ) : (
                "Sign Up"
              )}
            </motion.button>
          </form>
        </div>
        <div className="px-8 py-4 bg-gray-900 bg-opacity-50 flex justify-center">
          <p className="text-sm text-gray-400">
            Already have an admin account?{" "}
            <Link
              to={"/admin/login"}
              className="text-purple-400 hover:underline"
            >
              Login
            </Link>
          </p>
        </div>
      </motion.div>
    </AuthLayout>
    );
};

export default AdminSignUpPage;
