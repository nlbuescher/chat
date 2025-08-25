import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar, type AppSidebarProps } from "@/components/app-sidebar";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";

const data: AppSidebarProps = {
  navMain: [
    {
      title: "Chats",
      url: "#",
      items: [
        { title: "Welcome chat", url: "#" },
        { title: "Shopping list", url: "#" },
        { title: "Project ideas", url: "#" },
        { title: "Meeting notes", url: "#" },
      ],
    },
  ],
}

export default function Home() {
  return (
    <SidebarProvider>
      <AppSidebar {...data} />
      <SidebarInset className="flex flex-col h-screen">
        <header className="flex h-16 shrink-0 items-center gap-2 border-b px-4">
          <SidebarTrigger className="-ml-1" />
        </header>

        <main className="flex-1 flex flex-col">
          {/* Chat area */}
          <div className="flex-1 overflow-hidden">
            <div className="h-full flex flex-col">
              <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-background">
                {/* AI message */}
                <div className="max-w-prose rounded-md bg-muted p-4 text-sm text-muted-foreground">
                  <div className="font-medium mb-1">Assistant</div>
                  <div>Hi — this is a placeholder AI message. It appears on the left.</div>
                </div>

                {/* User message */}
                <div className="flex justify-end">
                  <div className="max-w-[60%] rounded-md bg-primary text-primary-foreground p-4 text-sm">
                    <div className="font-medium mb-1 text-right">You</div>
                    <div className="text-right">This is a placeholder user message aligned to the right.</div>
                  </div>
                </div>

                {/* More messages */}
                <div className="max-w-prose rounded-md bg-muted p-4 text-sm text-muted-foreground">
                  <div className="font-medium mb-1">Assistant</div>
                  <div>Another AI reply to demonstrate scroll behavior and styling.</div>
                </div>

                <div className="flex justify-end">
                  <div className="max-w-[60%] rounded-md bg-primary text-primary-foreground p-4 text-sm">
                    <div className="font-medium mb-1 text-right">You</div>
                    <div className="text-right">Another user message sample.</div>
                  </div>
                </div>
              </div>

              {/* Input bar */}
              <div className="border-t px-4 py-3 bg-background">
                <div className="max-w-4xl mx-auto flex gap-2">
                  <Textarea className="flex-1 resize-none" placeholder="Type a message..." />
                  <Button>Send</Button>
                </div>
              </div>
            </div>
          </div>
        </main>
      </SidebarInset>
    </SidebarProvider>
  );
}
