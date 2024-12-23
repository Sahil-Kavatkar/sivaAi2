import { useEffect, useRef, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { motion } from "framer-motion";
import toast from "react-hot-toast";
import AuthLayout from './AuthLayout';

const AdminOTPVerificationPage = () => {
  const [code, setCode] = useState(["", "", "", "", "", ""]);
  const inputRefs = useRef([]);
  const navigate = useNavigate();
  const { state } = useLocation(); // Access the state passed from the login page
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  // Get the QR code from the state
  const qrCode = state?.qrCode;

  const handleChange = (index, value) => {
    const newCode = [...code];

    if (value.length > 1) {
      const pastedCode = value.slice(0, 6).split("");
      for (let i = 0; i < 6; i++) {
        newCode[i] = pastedCode[i] || "";
      }
      setCode(newCode);

      const lastFilledIndex = newCode.findLastIndex((digit) => digit !== "");
      const focusIndex = lastFilledIndex < 5 ? lastFilledIndex + 1 : 5;
      inputRefs.current[focusIndex].focus();
    } else {
      newCode[index] = value;
      setCode(newCode);

      if (value && index < 5) {
        inputRefs.current[index + 1].focus();
      }
    }
  };

  const handleKeyDown = (index, e) => {
    if (e.key === "Backspace" && !code[index] && index > 0) {
      inputRefs.current[index - 1].focus();
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    const otp = code.join("");

    try {
      const response = await fetch("http://localhost:8080/adminverify-otp", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ otp }),
        credentials: "include", // Ensure session is maintained if needed
      });

      const data = await response.json();

      if (response.ok) {
        navigate("/admin/dash"); 
        toast.success("OTP verified successfully!");
      } else {
        console.error("Backend error:", data);
        setError(data.message || "Invalid OTP. Please try again.");
      }
    } catch (error) {
      console.error("Fetch error:", error);
      setError("Something went wrong. Please try again.");
    }

    setIsLoading(false);
  };

  useEffect(() => {
    if (code.every((digit) => digit !== "")) {
      handleSubmit(new Event("submit"));
    }
  }, [code]);

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
        Verify OTP
      </h2>
      <p className="text-center text-gray-300 mb-6">
        Scan the QR code to get your OTP.
      </p>

      {/* QR Code Display */}
      {qrCode && (
        <div className="text-center mb-6">
          <img
            src={qrCode}
            alt="QR Code for OTP"
            className="w-48 h-48 mx-auto"
          />
          <p className="text-gray-300 mt-2">Scan with your authentication app.</p>
        </div>
      )}

      {/* OTP Input Form */}
      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="flex justify-between">
          {code.map((digit, index) => (
            <input
              key={index}
              ref={(el) => (inputRefs.current[index] = el)}
              type="text"
              maxLength="1"
              value={digit}
              onChange={(e) => handleChange(index, e.target.value)}
              onKeyDown={(e) => handleKeyDown(index, e)}
              className="w-12 h-12 text-center text-2xl font-bold bg-gray-800 text-white border border-gray-700 rounded-lg focus:border-purple-500 focus:outline-none"
            />
          ))}
        </div>
        {error && <p className="text-red-500 font-semibold mt-2">{error}</p>}

        {/* Verify Button */}
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          type="submit"
          disabled={isLoading || code.some((digit) => !digit)}
          className="w-full bg-gradient-to-r from-purple-500 to-purple-600 text-white font-bold py-3 px-4 rounded-lg shadow-lg hover:from-purple-600 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-opacity-50 disabled:opacity-50"
        >
          {isLoading ? "Verifying..." : "Verify OTP"}
        </motion.button>
      </form>
    </div>
  </motion.div>
</AuthLayout>

  );
};

export default AdminOTPVerificationPage;
