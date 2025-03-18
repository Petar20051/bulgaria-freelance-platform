"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

interface Profile {
  email: string;
  userName: string;
  twoFactorEnabled: boolean;
}

export default function ProfilePage() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [message, setMessage] = useState("");
  const router = useRouter();

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
      return;
    }
    fetch("/api/auth/profile", {
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
    })
      .then(async (res) => {
        if (res.ok) {
          const data: Profile = await res.json();
          setProfile(data);
        } else {
          setMessage("Failed to fetch profile. Please log in again.");
          localStorage.removeItem("token");
          router.push("/login");
        }
      })
      .catch((err) => {
        setMessage("Error: " + err.message);
      });
  }, [router]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-400 to-blue-500 flex items-center justify-center">
      <div className="max-w-lg w-full bg-white p-8 rounded-lg shadow-lg">
        <h1 className="text-3xl font-bold text-center mb-6">Your Profile</h1>
        {profile ? (
          <div className="space-y-4">
            <div className="flex justify-between">
              <span className="font-medium">Email:</span>
              <span className="text-gray-700">{profile.email}</span>
            </div>
            <div className="flex justify-between">
              <span className="font-medium">Username:</span>
              <span className="text-gray-700">{profile.userName}</span>
            </div>
            <div className="flex justify-between">
              <span className="font-medium">2FA Enabled:</span>
              <span className="text-gray-700">
                {profile.twoFactorEnabled ? "Yes" : "No"}
              </span>
            </div>
          </div>
        ) : (
          <p className="text-center text-red-600 font-medium">
            {message || "Loading profile..."}
          </p>
        )}
      </div>
    </div>
  );
}
