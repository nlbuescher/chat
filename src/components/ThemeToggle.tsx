"use client";

import { useEffect, useState } from "react";
import { useTheme } from "next-themes";

export default function ThemeToggle() {
	let [mounted, setMounted] = useState(false);
	let { systemTheme, theme, setTheme } = useTheme();

	let currentTheme = theme === "system" ? systemTheme : theme;

	useEffect(() => setMounted(true));

	if (!mounted) {
		return null;
	}

	return (
		<button
			onClick={() => setTheme(currentTheme === "dark" ? "light" : "dark")}
			className="relative inline-flex h-6 w-12 items-center rounded-full transition-colors duration-200 ease-in-out outline-none ring-2 ring-offset-2 ring-foreground ring-offset-background m-1"
		>
			<span
				className="inline-flex items-center h-6 w-6 transform transition duration-200 ease-in-out translate-x-0 dark:translate-x-6"
			>
				<img className="dark:invert" src={currentTheme === "dark" ? "icon-moon.svg" : "icon-sun.svg"} />
			</span>
		</button>
	);
}
