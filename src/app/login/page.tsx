"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { zodResolver } from "@hookform/resolvers/zod";
import { SubmitHandler, useForm } from "react-hook-form";
import toast from "react-hot-toast";
import { LoginUserInput, LoginUserSchema } from "@/lib/validations/user.schema";
import Link from "next/link";

export default function LoginPage() {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<LoginUserInput>({
    resolver: zodResolver(LoginUserSchema),
  });
  const router = useRouter();
  const [loading, setLoading] = useState(false);

  const onSubmit: SubmitHandler<LoginUserInput> = async (data) => {
    const toastId = toast.loading("trying to validate");

    try {
      setLoading(true);
      const res = await fetch("/api/login", {
        method: "POST",
        body: JSON.stringify(data),
      });
      if (!res.ok) {
        toast.error("Username or password invalid");
      } else {
        const data = await res.json();
        toast.success(data.status as string);
        const toastId = toast.loading("Redirecting...");
        toast.dismiss(toastId);
        reset();
        router.push("/");
      }
      console.log(res);
    } catch (err: any) {
      toast.error(err.message);
    } finally {
      setLoading(false);
      toast.dismiss(toastId);
    }
  };

  return (
    <div className="flex flex-col gap-8 justify-center items-center w-full h-screen">
      <h1 className="text-2xl  font-black ">JWT SignIn</h1>

      <form
        onSubmit={handleSubmit(onSubmit)}
        className="w-full lg:max-w-md md:max-w-xl max-w-max p-2 bg-white/90 rounded-[3px] shadow-lg shadow-gray-400 md:p-4 "
      >
        <div className="  min-w-3xl flex flex-col gap-6 w-full  mb-6 ">
          {/* Username */}
          <div className="w-full min-w-[100%] ">
            <label className="label">Email </label>
            <input
              type="email"
              {...register("email")}
              placeholder="abc@gmail.com"
              className="form"
            />
            <p className="error">{errors.email?.message}</p>
          </div>
          {/* Password */}
          <div className="w-full min-w-[100%] ">
            <label className="label">Password</label>
            <input
              type="password"
              {...register("password")}
              placeholder="Password"
              className="form"
            />
            <p className="error">{errors.password?.message}</p>
          </div>
        </div>

        <button type="submit" className="btn">
          Login
        </button>
        {/* Sign in for an account */}
        <Link
          href={`/register`}
          className=" pt-[20px]  mx-auto text-center  my-2 w-fit m-4 justify-center items-center content-center justify-items-center "
        >
          <div className="">
            <span className="text-center  mx-auto cursor-pointer hover:underline underline-offset-1 decoration-black_02 ">
              Don&lsquo;t have an account?
              <strong className="ml-[2px]">Sign up</strong>
            </span>
          </div>
        </Link>
      </form>
    </div>
  );
}
