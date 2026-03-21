import type { ButtonHTMLAttributes, ReactNode } from 'react';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary';
  children: ReactNode;
}

export default function Button({
  variant = 'primary',
  children,
  className = '',
  ...props
}: ButtonProps) {
  const base = variant === 'primary' ? 'btn-primary' : 'btn-secondary';

  return (
    <button className={`${base} ${className}`} {...props}>
      {children}
    </button>
  );
}
