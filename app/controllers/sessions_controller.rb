class SessionsController < ApplicationController
  def new
  end

  #Initializes both a temporary and persistant session.
  #Finds the user by the email entered in the form.
  #Checks if the user is valid and if the password entered matches the password
  #hash (password digest) using built-in has_secure_password authenticate. if
  #true, creates a temporary session using log_in. If remember me is checked,
  # creates a persistant session using remember. Redirects to the user's
  #profile page.
  #If fails, show error message and re-render the page.

  def create
    user = User.find_by(email: params[:session][:email].downcase)
    if user && user.authenticate(params[:session][:password])
      log_in user
      params[:session][:remember_me] == '1' ? remember(user) : forget(user)
      redirect_to user
    else
      flash.now[:danger] = 'Invalid email/ password combination'
      render 'new'
    end
  end

  #Checks if a user is currently logs in, and if so destroys the temporary and
  #persistant sessions and nil the current user.
  #Redirects to the home page.
  def destroy
    log_out if logged_in?
    redirect_to root_url
  end

end
