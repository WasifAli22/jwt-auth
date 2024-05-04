import { cookies } from "next/dist/client/components/headers";
import toast from "react-hot-toast";
import Logout from "./Logout";


const UserInfo = async () => {
  let token: string | undefined;
  let data: any[] = [];
  if (cookies().has("token")) {
    token = cookies().get("token")?.value;
  }
  const res = await fetch(`${process.env.URL}api/users/me`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      //   "X-USER-ID": "13",
      Authorization: `Bearer ${token}`,
    },
  });
  if (res.ok) {
    const session = await res.json();
    data.push(session);
    
  }
  
  return (
    <div>
      <Logout token={token as string} />
      <pre>{JSON.stringify(data, null, 2)}</pre>
    </div>
  );
};

export default UserInfo;
