"use client";

import { cn } from "@/lib/utils";
import ModeToggle from "@/components/mode-toggle";
import { Button } from "@/components/ui/button";
import {
  SidebarContent,
  SidebarHeader,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  Sidebar,
} from "@/components/ui/sidebar";

export type AppSidebarMenuItemProps = AppSidebarMenuSubItemProps & {
  items: AppSidebarMenuSubItemProps[];
};

export type AppSidebarMenuSubItemProps = {
  title: string;
  url: string;
  isActive?: boolean;
};

export type AppSidebarProps = React.ComponentProps<typeof Sidebar> & {
  navMain: AppSidebarMenuItemProps[];
};

export function AppSidebar({ navMain, className, ...props }: AppSidebarProps) {
  return (
    <Sidebar className={cn("h-screen", className)} {...props}>
      <SidebarContent>
        <SidebarHeader className="border-b">
          <Button className="w-full" variant="outline" size="sm">
            New chat
          </Button>
        </SidebarHeader>

        {navMain.map((item) => {
          return (
            <SidebarGroup key={item.title}>
              <SidebarGroupLabel>{item.title}</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {item.items.map((subItem) => {
                    return (
                      <SidebarMenuItem key={subItem.title}>
                        <SidebarMenuButton asChild isActive={subItem.isActive}>
                          <a href={subItem.url}>{subItem.title}</a>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    );
                  })}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          );
        })}

        <div className="mt-auto flex items-center gap-2 p-2">
          <ModeToggle className="ml-auto" />
        </div>
      </SidebarContent>
    </Sidebar>
  );
}
