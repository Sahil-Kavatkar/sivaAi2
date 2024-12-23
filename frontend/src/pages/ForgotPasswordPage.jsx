import { motion } from "framer-motion";
import { useState } from "react";
import Input from "../components/Input";
import { ArrowLeft, Loader, Mail } from "lucide-react";
import { Link } from "react-router-dom";
import toast from "react-hot-toast";
import AuthLayout from './AuthLayout';

const ForgotPasswordPage = () => {
  const [email, setEmail] = useState("");
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await fetch("http://localhost:8080/forgot-password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email }),
      });

      if (response.ok) {
        toast.success("If the email exists, a reset link will be sent shortly.");
        setIsSubmitted(true);
      } else {
        const data = await response.json();
        toast.error(data.message || "Failed to send reset link. Please try again.");
      }
    } catch (error) {
      console.error("Error sending reset link:", error);
      toast.error("Something went wrong. Please try again later.");
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
    {/* Header Section */}
    <div className="w-full max-w-lg p-8">
      <h2 className="text-4xl font-bold text-white mb-6 text-center bg-gradient-to-r from-white to-gray-500 text-transparent bg-clip-text">
        Forgot Password
      </h2>

      {!isSubmitted ? (
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Instructions */}
          <p className="text-gray-300 text-center mb-6">
            Enter your email address and we'll send you a link to reset your password.
          </p>

          {/* Email Input */}
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Email Address</label>
            <Input
              icon={Mail}
              type="email"
              placeholder="Email Address"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-purple-600 focus:border-transparent"
            />
          </div>

          {/* Submit Button */}
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            className="w-full py-3 px-4 bg-gradient-to-r from-purple-500 to-purple-600 text-white font-bold rounded-lg shadow-lg hover:from-purple-600 hover:to-emerald-700 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-opacity-50 transition duration-200"
            type="submit"
            disabled={isLoading}
          >
            {isLoading ? <Loader className="w-6 h-6 animate-spin mx-auto" /> : "Send Reset Link"}
          </motion.button>
        </form>
      ) : (
        <div className="text-center">
          {/* Success Icon */}
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ type: "spring", stiffness: 500, damping: 30 }}
            className="w-16 h-16 bg-purple-500 rounded-full flex items-center justify-center mx-auto mb-4"
          >
            <Mail className="h-8 w-8 text-white" />
          </motion.div>

          {/* Success Message */}
          <p className="text-gray-300 mb-6">
            If an account exists for {email}, you will receive a password reset link shortly.
          </p>
        </div>
      )}
    </div>

    {/* Back to Login Link */}
    <div className="px-8 py-4 bg-gray-900 bg-opacity-50 flex justify-center">
      <Link to="/login" className="text-sm text-purple-400 hover:underline flex items-center">
        <ArrowLeft className="h-4 w-4 mr-2" /> Back to Login
      </Link>
    </div>
  </motion.div>
</AuthLayout>

  );
};

export default ForgotPasswordPage;
