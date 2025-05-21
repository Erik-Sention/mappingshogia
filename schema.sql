-- Create users table
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT,
    role TEXT DEFAULT 'user',
    "Organization" TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create function to handle new user registration
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.users (id, email, username, full_name, role, "Organization")
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'username', split_part(NEW.email, '@', 1)),
        COALESCE(NEW.raw_user_meta_data->>'full_name', ''),
        COALESCE(NEW.raw_user_meta_data->>'role', 'user'),
        COALESCE(NEW.raw_user_meta_data->>'Organization', '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger for new user registration
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Create items table if it doesn't exist yet
CREATE TABLE IF NOT EXISTS public.items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    text TEXT NOT NULL,
    entity TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    position INTEGER NOT NULL,
    category TEXT NOT NULL,
    user_id UUID REFERENCES public.users(id),
    resource_id UUID REFERENCES public.resources(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create resources table
CREATE TABLE IF NOT EXISTS public.resources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    text TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    user_id UUID REFERENCES public.users(id)
);

-- Enable Row Level Security
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.resources ENABLE ROW LEVEL SECURITY;

-- Create policies
CREATE POLICY "Users can view all users" ON public.users
    FOR SELECT USING (true);

CREATE POLICY "Users can update their own data" ON public.users
    FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Users can view all items" ON public.items
    FOR SELECT USING (true);

CREATE POLICY "Users can insert items" ON public.items
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own items" ON public.items
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own items" ON public.items
    FOR DELETE USING (auth.uid() = user_id);

-- Create policies for resources
CREATE POLICY "Users can view resources in same organization" ON public.resources
    FOR SELECT USING (
        -- Allow if user_id is null (anonymous resource)
        user_id IS NULL 
        OR 
        -- Or if user_id matches the authenticated user
        auth.uid() = user_id
        OR
        -- Or if the user is in the same organization as the resource creator
        EXISTS (
            SELECT 1 FROM public.users u1, public.users u2
            WHERE u1.id = auth.uid() 
            AND u2.id = user_id
            AND u1."Organization" = u2."Organization"
            AND u1."Organization" IS NOT NULL
        )
    );

CREATE POLICY "Users can insert resources" ON public.resources
    FOR INSERT WITH CHECK (
        -- Allow if user_id is null (anonymous resource)
        user_id IS NULL 
        OR 
        -- Or if user_id matches the authenticated user
        auth.uid() = user_id
    );

CREATE POLICY "Users can update resources" ON public.resources
    FOR UPDATE USING (
        -- Allow if user_id is null (anonymous resource)
        user_id IS NULL 
        OR 
        -- Or if user_id matches the authenticated user
        auth.uid() = user_id
    );

CREATE POLICY "Users can delete resources" ON public.resources
    FOR DELETE USING (
        -- Allow if user_id is null (anonymous resource)
        user_id IS NULL 
        OR 
        -- Or if user_id matches the authenticated user
        auth.uid() = user_id
    ); 