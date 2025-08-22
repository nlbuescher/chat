"use client";

import { cn } from "@/lib/utils";
import {
	SidebarContent,
	SidebarGroup,
	SidebarGroupContent,
	SidebarGroupLabel,
	SidebarMenu,
	SidebarMenuButton,
	SidebarMenuItem,
	Sidebar,
} from "@/components/ui/sidebar";

export type AppSidebarMenuItemProps = AppSidebarMenuSubItemProps & {
	items: AppSidebarMenuSubItemProps[],
};

export type AppSidebarMenuSubItemProps = {
	title: string,
	url: string,
	isActive?: boolean,
};

export type AppSidebarProps = React.ComponentProps<typeof Sidebar> & {
	navMain: AppSidebarMenuItemProps[]
};

export function AppSidebar({ navMain, className, ...props }: AppSidebarProps) {
	return (
		<Sidebar className={cn("h-screen", className)} {...props}>
			<SidebarContent>
				{navMain.map((item) => {
					return <SidebarGroup key={item.title}>
						<SidebarGroupLabel>{item.title}</SidebarGroupLabel>
						<SidebarGroupContent>
							<SidebarMenu>
								{item.items.map((subItem) => {
									return <SidebarMenuItem key={subItem.title}>
										<SidebarMenuButton asChild isActive={subItem.isActive}>
											<a href={subItem.url}>{subItem.title}</a>
										</SidebarMenuButton>
									</SidebarMenuItem>
								})}
							</SidebarMenu>
						</SidebarGroupContent>
					</SidebarGroup>
				})}
			</SidebarContent>
		</Sidebar>
	);
}
