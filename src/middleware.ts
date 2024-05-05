import { NextRequest, NextResponse } from "next/server";
import { getErrorResponse } from "./lib/helpers";
import { verifyJWT } from "./lib/token";

export const middleware = async (request: NextRequest) => {

  let token: string | undefined;

  if (request.cookies.has("token")) {
    token = request.cookies.get("token")?.value;
  } else if (request.headers.get("Authorization")?.startsWith("Bearer ")) {
    token = request.headers.get("Authorization")?.substring(7);
  }

  const { pathname, origin } = request.nextUrl;
  console.log("token = ", token);


  if (pathname === "/login") {
    if (token) return NextResponse.redirect(`${origin}/admin`);
    return NextResponse.next();
  }
  if (pathname === "/admin") {
    if (!token) return NextResponse.redirect(`${origin}/login`);
    return NextResponse.next();
  }

  if (!token && pathname.startsWith("/admin") || pathname.startsWith("/:path*")) {
    return NextResponse.redirect(`${origin}/login`);
  }
  if (!token && pathname.startsWith("/api")) {
    return getErrorResponse(
      401,
      "You are not logged in. Please provide a token to gain access."
    );
  }
  const response = NextResponse.next();
  try {

    if (token) {
      const { sub } = await verifyJWT<{ sub: string }>(token);
      response.headers.set("X-USER-ID", sub); // ? 
    }
  } catch (error) {
    if (pathname.startsWith("/api")) {
      return getErrorResponse(
        401,
        "Token is invalid or user doesn't exists"
      );
    }
  }
  return response
};
export const config = {
  matcher: ["/login", "/admin", "/api/login",]
};

