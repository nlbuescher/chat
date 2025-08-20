"use client";

import { useEffect, useState } from "react";
import { useTheme } from "next-themes";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Sun, Moon, SunMoon } from "lucide-react";

export default function ModeToggle() {
	let [mounted, setMounted] = useState(false);
	let { theme, setTheme } = useTheme();

	useEffect(() => setMounted(true));

	if (!mounted) {
		return null;
	}

	let props = {
		className: "h-[1.2rem] w-[1.2rem] transition-all"
	};

	return (
		<DropdownMenu>
			<DropdownMenuTrigger asChild>
				<Button variant="outline" size="icon">
					{theme === "light" ? <Sun {...props} /> : theme === "dark" ? <Moon {...props} /> : <SunMoon {...props} />}
					<span className="sr-only">Toggle theme</span>
				</Button>
			</DropdownMenuTrigger>
			<DropdownMenuContent align="end">
				<DropdownMenuItem onClick={() => setTheme("light")}>
					Light
				</DropdownMenuItem>
				<DropdownMenuItem onClick={() => setTheme("dark")}>
					Dark
				</DropdownMenuItem>
				<DropdownMenuItem onClick={() => setTheme("system")}>
					System
				</DropdownMenuItem>
			</DropdownMenuContent>
		</DropdownMenu>
	);
}
