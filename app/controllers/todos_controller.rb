class TodosController < ApplicationController
  before_action :set_todo, only: %i[show update destroy]

  # GET /todos
  def index
    # @todos = Todo.all
    # json_response(@todos)
    # ______________________
    # get current user todos
    @todos = current_user.todos
    json_response(@todos)
  end

  # POST /todos
  def create
    # @todo = Todo.create!(todo_params)
    # json_response(@todo, :created)
    # ______________________________________
    # create todos belonging to current user
    @todo = current_user.todos.create!(todo_params)
    json_response(@todo, :created)
  end

  # GET /todos/:id
  def show
    json_response(@todo)
  end

  # PUT /todos/:id
  def update
    @todo.update(todo_params)
    head :no_content
  end

  # DELETE /todos/:id
  def destroy
    @todo.destroy
    head :no_content
  end

  private

  def todo_params
    # whitelist params
    # params.permit(:title, :created_by)
    # _____________________________________________________
    # remove `created_by` from list of permitted parameters
    params.permit(:title)
  end

  def set_todo
    @todo = Todo.find(params[:id])
  end
end
