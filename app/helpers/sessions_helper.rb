module SessionsHelper

  #Creates a temporary session which persists until the browser is closed or
  #the user logs out
  def log_in(user)
    session[:user_id] = user.id
  end

  #Calls user.remember to generate a remember token and to store its digest to
  #the db. Sets a local permanent cookie of the encrypted user_id and the
  #remember token.
  def remember(user)
    user.remember
    cookies.permanent.signed[:user_id] = user.id
    cookies.permanent[:remember_token] = user.remember_token
  end

  #Returns true if a given user is the current user
  def current_user?(user)
    user == current_user
  end

  #Gets the current app user based on the session.
  #Checks temporary session for existance of a user id, and sets the current
  #user to this value, if it exists.
  #Else if a persistant user ID exists in cookies, finds the User by this ID
  #and validates that the user is valid and that the remember_token in cookies
  #matches remember_digest in the DB.  If true, creates a temporary session
  #for the user and sets the value of current_user to this user.
  def current_user
    if (user_id = session[:user_id])
      @current_user ||= User.find_by(id: user_id)
    elsif (user_id = cookies.signed[:user_id])
      user = User.find_by(id: user_id)
      if user && user.authenticated?(:remember, cookies[:remember_token])
        log_in user
        @current_user = user
      end
    end
  end

  def logged_in?
    !current_user.nil?
  end

  #Nils the remember_digest value for the user and deletes the cookie for the
  #user_id and remember_token
  def forget(user)
    user.forget
    cookies.delete(:user_id)
    cookies.delete(:remember_token)
  end

  #Terminates the session by niling the persistant cookie and remember_digest
  #values, deleting the temporary session, and setting the current_user to nil.
  def log_out
    forget(current_user)
    session.delete(:user_id)
    @current_user = nil
  end

  def redirect_back_or(default)
    redirect_to(session[:forwarding_url] || default)
    session.delete(:forwarding_url)
  end

  def store_location
    session[:forwarding_url] = request.original_url if request.get?
  end

end
