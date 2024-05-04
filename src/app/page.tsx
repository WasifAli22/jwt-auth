import Image from 'next/image'
import UserInfo from '@/components/userInfo'

export default function Home() {
  
  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
       <UserInfo />
    </main>
  )
}
